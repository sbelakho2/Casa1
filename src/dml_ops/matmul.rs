//! Matmul portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_gemm(&self, trans_a: bool, trans_b: bool, beta: f32) -> DmlResult<()> {
        if !(2..=3).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "GEMM requires 2 or 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let a = &self.inputs[0];
        let b = &self.inputs[1];
        let rank = a.sizes.len();
        if rank < 2 {
            return Err(DmlError::invalid("GEMM tensors must have rank >= 2"));
        }
        if b.sizes.len() != rank || self.output.sizes.len() != rank {
            return Err(DmlError::invalid(
                "GEMM input and output tensors must have the same rank",
            ));
        }
        let (m, k) = if trans_a {
            (a.sizes[rank - 1], a.sizes[rank - 2])
        } else {
            (a.sizes[rank - 2], a.sizes[rank - 1])
        };
        let (b_k, n) = if trans_b {
            (b.sizes[rank - 1], b.sizes[rank - 2])
        } else {
            (b.sizes[rank - 2], b.sizes[rank - 1])
        };
        if k != b_k {
            return Err(DmlError::invalid(format!(
                "GEMM inner dimensions do not match: A K={k}, B K={b_k}"
            )));
        }
        if self.output.sizes[rank - 2] != m || self.output.sizes[rank - 1] != n {
            return Err(DmlError::invalid(format!(
                "GEMM output sizes must be [{m}, {n}], got [{}, {}]",
                self.output.sizes[rank - 2],
                self.output.sizes[rank - 1]
            )));
        }
        if a.sizes[..rank - 2] != b.sizes[..rank - 2]
            || a.sizes[..rank - 2] != self.output.sizes[..rank - 2]
        {
            return Err(DmlError::invalid(
                "GEMM batch dimensions must match across A, B, and output",
            ));
        }
        if beta != 0.0 && self.inputs.len() == 2 {
            return Err(DmlError::invalid(
                "GEMM beta is non-zero but no C tensor was provided",
            ));
        }
        if let Some(c) = self.inputs.get(2) {
            if c.sizes.len() != rank {
                return Err(DmlError::invalid(
                    "GEMM C tensor must have the same rank as the output",
                ));
            }
            if c.sizes != self.output.sizes {
                return Err(DmlError::invalid(
                    "GEMM C tensor must have the output sizes",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn emit_gemm_msl(
    plan: &DmlOpPlan,
    trans_a: bool,
    trans_b: bool,
    alpha: f32,
    beta: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let a = &plan.inputs[0];
    let b = &plan.inputs[1];
    let rank = a.sizes.len();
    let m = plan.output.sizes[rank - 2];
    let n = plan.output.sizes[rank - 1];
    let k = if trans_a {
        a.sizes[rank - 2]
    } else {
        a.sizes[rank - 1]
    };
    let (a_m_stride, a_k_stride) = if trans_a {
        (a.strides[rank - 1], a.strides[rank - 2])
    } else {
        (a.strides[rank - 2], a.strides[rank - 1])
    };
    let (b_k_stride, b_n_stride) = if trans_b {
        (b.strides[rank - 1], b.strides[rank - 2])
    } else {
        (b.strides[rank - 2], b.strides[rank - 1])
    };
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    uint inner = gid % {}u;\n",
        m as u64 * n as u64
    ));
    source.push_str(&format!("    uint m = inner / {n}u;\n"));
    source.push_str(&format!("    uint n = inner % {n}u;\n"));
    source.push_str(&format!(
        "    uint batch = gid / {}u;\n",
        m as u64 * n as u64
    ));
    let mut a_batch = vec!["0u".to_string()];
    let mut b_batch = vec!["0u".to_string()];
    let mut c_batch = vec!["0u".to_string()];
    if rank > 2 {
        source.push_str("    uint rem = batch;\n");
        for dimension in 0..rank - 2 {
            let size = plan.output.sizes[dimension];
            source.push_str(&format!("    uint bc{dimension} = rem % {size}u;\n"));
            source.push_str(&format!("    rem /= {size}u;\n"));
            a_batch.push(format!("bc{dimension} * {}u", a.strides[dimension]));
            b_batch.push(format!("bc{dimension} * {}u", b.strides[dimension]));
            if let Some(c) = plan.inputs.get(2) {
                c_batch.push(format!("bc{dimension} * {}u", c.strides[dimension]));
            }
        }
    }
    let a_batch_expr = a_batch.join(" + ");
    let b_batch_expr = b_batch.join(" + ");
    let c_batch_expr = c_batch.join(" + ");
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!("    for (uint kk = 0u; kk < {k}u; ++kk) {{\n"));
    let a_terms = format!("m * {a_m_stride}u + kk * {a_k_stride}u");
    let b_terms = format!("kk * {b_k_stride}u + n * {b_n_stride}u");
    source.push_str(&format!(
        "        uint a_idx = {a_batch_expr} + {a_terms};\n"
    ));
    source.push_str(&format!(
        "        uint b_idx = {b_batch_expr} + {b_terms};\n"
    ));
    source.push_str(&format!(
        "        acc += {} * {};\n",
        msl_load_float(&plan.inputs[0], "in0", "a_idx"),
        msl_load_float(&plan.inputs[1], "in1", "b_idx")
    ));
    source.push_str("    }\n");
    source.push_str(&format!("    float value = {} * acc;\n", msl_float(alpha)));
    if plan.inputs.len() == 3 {
        let c = &plan.inputs[2];
        source.push_str(&format!(
            "    uint c_idx = {c_batch_expr} + m * {}u + n * {}u;\n",
            c.strides[rank - 2],
            c.strides[rank - 1]
        ));
        source.push_str(&format!(
            "    value += {} * float(in2[c_idx]);\n",
            msl_float(beta)
        ));
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})value;\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}
