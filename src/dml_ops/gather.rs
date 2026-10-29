//! Gather portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_gather(&self, axis: u32, index_dimensions: u32) -> DmlResult<()> {
        if self.inputs.len() != 2 {
            return Err(DmlError::invalid(format!(
                "gather requires 2 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        let rank = input.sizes.len();
        if axis as usize >= rank {
            return Err(DmlError::invalid(format!(
                "gather axis {axis} is out of range for rank {rank}"
            )));
        }
        if index_dimensions != 1 || indices.sizes.len() != 1 {
            return Err(DmlError::invalid(
                "gather supports only a rank-1 indices tensor with IndexDimensions 1",
            ));
        }
        if !indices.is_contiguous() {
            return Err(DmlError::invalid(
                "gather indices tensor must be contiguous",
            ));
        }
        let mut expected = input.sizes.clone();
        expected[axis as usize] = indices.sizes[0];
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "gather output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_gather_elements(&self, axis: u32) -> DmlResult<()> {
        if self.inputs.len() != 2 {
            return Err(DmlError::invalid(format!(
                "gather elements requires 2 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        if input.sizes.len() != indices.sizes.len() {
            return Err(DmlError::invalid(
                "gather elements input and indices must have the same rank",
            ));
        }
        if axis as usize >= input.sizes.len() {
            return Err(DmlError::invalid(format!(
                "gather elements axis {axis} is out of range for rank {}",
                input.sizes.len()
            )));
        }
        if self.output.sizes != indices.sizes {
            return Err(DmlError::invalid(format!(
                "gather elements output sizes must equal the indices sizes {:?}, got {:?}",
                indices.sizes, self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_gather_nd(
        &self,
        input_dimension_count: u32,
        indices_dimension_count: u32,
        batch_dimension_count: u32,
    ) -> DmlResult<()> {
        if self.inputs.len() != 2 {
            return Err(DmlError::invalid(format!(
                "gather-nd requires 2 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        let input_rank = input.sizes.len();
        let indices_rank = indices.sizes.len();
        if indices_rank < 1 {
            return Err(DmlError::invalid(
                "gather-nd indices tensor must have rank >= 1",
            ));
        }
        if input_dimension_count != 0 && input_dimension_count != input_rank as u32 {
            return Err(DmlError::invalid(format!(
                "gather-nd InputDimensionCount {input_dimension_count} must be 0 or {input_rank}"
            )));
        }
        if indices_dimension_count != 0 && indices_dimension_count != indices_rank as u32 {
            return Err(DmlError::invalid(format!(
                "gather-nd IndicesDimensionCount {indices_dimension_count} must be 0 or {indices_rank}"
            )));
        }
        let batch = batch_dimension_count as usize;
        if batch >= indices_rank {
            return Err(DmlError::invalid(format!(
                "gather-nd BatchDimensionCount {batch_dimension_count} leaves no index dimensions in a rank-{indices_rank} indices tensor"
            )));
        }
        if batch > input_rank {
            return Err(DmlError::invalid(format!(
                "gather-nd BatchDimensionCount {batch_dimension_count} exceeds the input rank {input_rank}"
            )));
        }
        if indices.sizes[..batch] != input.sizes[..batch] {
            return Err(DmlError::invalid(format!(
                "gather-nd batch dimensions {:?} must match the input batch dimensions {:?}",
                &indices.sizes[..batch],
                &input.sizes[..batch]
            )));
        }
        let indexed = indices.sizes[indices_rank - 1];
        if indexed as usize > input_rank - batch {
            return Err(DmlError::invalid(format!(
                "gather-nd indices last dimension {indexed} exceeds the indexed input rank {}",
                input_rank - batch
            )));
        }
        let mut expected = indices.sizes[..indices_rank - 1].to_vec();
        expected.extend_from_slice(&input.sizes[batch + indexed as usize..]);
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "gather-nd output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_scatter(&self, axis: u32) -> DmlResult<()> {
        if self.inputs.len() != 3 {
            return Err(DmlError::invalid(format!(
                "scatter requires 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        let updates = &self.inputs[2];
        let rank = input.sizes.len();
        if axis as usize >= rank {
            return Err(DmlError::invalid(format!(
                "scatter axis {axis} is out of range for rank {rank}"
            )));
        }
        if indices.sizes != updates.sizes {
            return Err(DmlError::invalid(
                "scatter indices and updates must have identical sizes",
            ));
        }
        if indices.sizes.len() != rank {
            return Err(DmlError::invalid(
                "scatter indices must have the same rank as the input",
            ));
        }
        for dimension in 0..rank {
            if dimension as u32 != axis && indices.sizes[dimension] != input.sizes[dimension] {
                return Err(DmlError::invalid(
                    "scatter indices sizes must match the input on non-axis dimensions",
                ));
            }
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "scatter output sizes must equal the input sizes",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_scatter_nd(
        &self,
        input_dimension_count: u32,
        indices_dimension_count: u32,
    ) -> DmlResult<()> {
        if self.inputs.len() != 3 {
            return Err(DmlError::invalid(format!(
                "scatter-nd requires 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        let updates = &self.inputs[2];
        let input_rank = input.sizes.len();
        let indices_rank = indices.sizes.len();
        if indices_rank < 1 {
            return Err(DmlError::invalid(
                "scatter-nd indices tensor must have rank >= 1",
            ));
        }
        if input_dimension_count != 0 && input_dimension_count != input_rank as u32 {
            return Err(DmlError::invalid(format!(
                "scatter-nd InputDimensionCount {input_dimension_count} must be 0 or {input_rank}"
            )));
        }
        if indices_dimension_count != 0 && indices_dimension_count != indices_rank as u32 {
            return Err(DmlError::invalid(format!(
                "scatter-nd IndicesDimensionCount {indices_dimension_count} must be 0 or {indices_rank}"
            )));
        }
        let indexed = indices.sizes[indices_rank - 1];
        if indexed as usize > input_rank {
            return Err(DmlError::invalid(format!(
                "scatter-nd indices last dimension {indexed} exceeds the input rank {input_rank}"
            )));
        }
        let mut expected_updates = indices.sizes[..indices_rank - 1].to_vec();
        expected_updates.extend_from_slice(&input.sizes[indexed as usize..]);
        if updates.sizes != expected_updates {
            return Err(DmlError::invalid(format!(
                "scatter-nd updates sizes must be {expected_updates:?}, got {:?}",
                updates.sizes
            )));
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "scatter-nd output sizes must equal the input sizes",
            ));
        }
        Ok(())
    }
}

pub(crate) fn emit_gather_msl(
    plan: &DmlOpPlan,
    axis: u32,
    _index_dimensions: u32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!("    int index = int(in1[o{axis}]);\n"));
    let mut coords = coord_names(input.sizes.len());
    let valid = format!("index >= 0 && index < {}", input.sizes[axis as usize]);
    coords[axis as usize] = "uint(index)".to_string();
    source.push_str(&format!(
        "    out[{}] = {valid} ? in0[{}] : ({scalar})0;\n",
        output_index_expr(&plan.output),
        linear_index(input, &coords)
    ));
    source.push_str("}\n");
    let _ = indices;
    Ok(source)
}

pub(crate) fn emit_gather_elements_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let index_coords = coord_names(indices.sizes.len());
    source.push_str(&format!(
        "    int index = int(in1[{}]);\n",
        linear_index(indices, &index_coords)
    ));
    let mut coords = coord_names(input.sizes.len());
    coords[axis as usize] = "uint(index)".to_string();
    source.push_str(&format!(
        "    out[{}] = (index >= 0 && index < {}) ? in0[{}] : ({scalar})0;\n",
        output_index_expr(&plan.output),
        input.sizes[axis as usize],
        linear_index(input, &coords)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_gather_nd_msl(
    plan: &DmlOpPlan,
    _input_dimension_count: u32,
    _indices_dimension_count: u32,
    batch_dimension_count: u32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let indices_rank = indices.sizes.len();
    let batch = batch_dimension_count as usize;
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut input_coords = Vec::with_capacity(input.sizes.len());
    for dimension in 0..input.sizes.len() {
        if dimension < batch {
            input_coords.push(format!("o{dimension}"));
        } else if dimension < batch + indexed {
            let index_dimension = dimension - batch;
            let mut idx_coords = vec![String::new(); indices_rank];
            for (position, coordinate) in idx_coords.iter_mut().take(indices_rank - 1).enumerate() {
                *coordinate = format!("o{position}");
            }
            idx_coords[indices_rank - 1] = format!("{index_dimension}u");
            let index_expr = linear_index(indices, &idx_coords);
            source.push_str(&format!("    int i{dimension} = int(in1[{index_expr}]);\n"));
            input_coords.push(format!(
                "uint(clamp(i{dimension}, 0, {}))",
                input.sizes[dimension] - 1
            ));
        } else {
            input_coords.push(format!(
                "o{}",
                indices_rank - 1 + dimension - batch - indexed
            ));
        }
    }
    let mut valid_terms = Vec::new();
    for dimension in 0..indexed {
        valid_terms.push(format!(
            "i{} >= 0 && i{} < {}",
            batch + dimension,
            batch + dimension,
            input.sizes[batch + dimension]
        ));
    }
    let condition = if valid_terms.is_empty() {
        "true".to_string()
    } else {
        valid_terms.join(" && ")
    };
    source.push_str(&format!(
        "    out[{}] = ({condition}) ? in0[{}] : ({scalar})0;\n",
        output_index_expr(&plan.output),
        linear_index(input, &input_coords)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_scatter_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let updates = &plan.inputs[2];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    out[{}] = in0[{}];\n",
        output_index_expr(&plan.output),
        linear_index(input, &coord_names(input.sizes.len()))
    ));
    let axis_size = indices.sizes[axis as usize];
    source.push_str(&format!(
        "    for (uint i = 0u; i < {axis_size}u; ++i) {{\n"
    ));
    let mut index_coords = coord_names(indices.sizes.len());
    index_coords[axis as usize] = "i".to_string();
    let mut update_coords = coord_names(updates.sizes.len());
    update_coords[axis as usize] = "i".to_string();
    source.push_str(&format!(
        "        int index = int(in1[{}]);\n",
        linear_index(indices, &index_coords)
    ));
    source.push_str(&format!(
        "        if (index == int(o{axis})) out[{}] = in2[{}];\n",
        output_index_expr(&plan.output),
        linear_index(updates, &update_coords)
    ));
    source.push_str("    }\n}\n");
    Ok(source)
}

pub(crate) fn emit_scatter_nd_msl(
    plan: &DmlOpPlan,
    _input_dimension_count: u32,
    _indices_dimension_count: u32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let updates = &plan.inputs[2];
    let indices_rank = indices.sizes.len();
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let update_count: u64 = indices.sizes[..indices_rank - 1]
        .iter()
        .map(|v| *v as u64)
        .product();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    out[{}] = in0[{}];\n",
        output_index_expr(&plan.output),
        linear_index(input, &coord_names(input.sizes.len()))
    ));
    source.push_str(&format!(
        "    for (uint u = 0u; u < {update_count}u; ++u) {{\n"
    ));
    source.push_str("        uint rem = u;\n");
    let mut update_coords = Vec::with_capacity(indices_rank);
    for dimension in 0..indices_rank - 1 {
        let size = indices.sizes[dimension];
        source.push_str(&format!("        uint uc{dimension} = rem % {size}u;\n"));
        source.push_str(&format!("        rem /= {size}u;\n"));
        update_coords.push(format!("uc{dimension}"));
    }
    source.push_str("        bool match = true;\n");
    for dimension in 0..indexed {
        let mut index_coords = update_coords.clone();
        index_coords.push(format!("{dimension}u"));
        source.push_str(&format!(
            "        match = match && int(in1[{}]) == int(o{dimension});\n",
            linear_index(indices, &index_coords)
        ));
    }
    let mut update_data_coords = Vec::new();
    for dimension in 0..indices_rank - 1 {
        update_data_coords.push(format!("uc{dimension}"));
    }
    for dimension in indexed..updates.sizes.len() {
        update_data_coords.push(format!("o{dimension}"));
    }
    source.push_str(&format!(
        "        if (match) out[{}] = in2[{}];\n",
        output_index_expr(&plan.output),
        linear_index(updates, &update_data_coords)
    ));
    source.push_str("    }\n}\n");
    Ok(source)
}

pub(crate) fn execute_gather_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    axis: u32,
    _index_dimensions: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let index = load_integer(inputs[1], output_coords[axis as usize], indices.data_type);
        let mut input_coords = output_coords.clone();
        input_coords[axis as usize] = index as u64;
        let value = if index >= 0 && (index as u64) < input.sizes[axis as usize] as u64 {
            load_scalar(
                inputs[0],
                index_of(&input_coords, &input.strides),
                input.data_type,
            )
        } else {
            0.0
        };
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            value,
        );
    }
    Ok(())
}

pub(crate) fn execute_gather_elements_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    axis: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let index = load_integer(
            inputs[1],
            index_of(&output_coords, &indices.strides),
            indices.data_type,
        );
        let mut input_coords = output_coords.clone();
        input_coords[axis as usize] = index as u64;
        let value = if index >= 0 && (index as u64) < input.sizes[axis as usize] as u64 {
            load_scalar(
                inputs[0],
                index_of(&input_coords, &input.strides),
                input.data_type,
            )
        } else {
            0.0
        };
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            value,
        );
    }
    Ok(())
}

pub(crate) fn execute_gather_nd_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    _input_dimension_count: u32,
    _indices_dimension_count: u32,
    batch_dimension_count: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let indices_rank = indices.sizes.len();
    let batch = batch_dimension_count as usize;
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let mut input_coords = Vec::with_capacity(input.sizes.len());
        let mut valid = true;
        for dimension in 0..batch {
            input_coords.push(output_coords[dimension]);
        }
        for dimension in 0..indexed {
            let mut index_coords = Vec::with_capacity(indices_rank);
            index_coords.extend_from_slice(&output_coords[..indices_rank - 1]);
            index_coords.push(dimension as u64);
            let index = load_integer(
                inputs[1],
                index_of(&index_coords, &indices.strides),
                indices.data_type,
            );
            if index < 0 || index as u64 >= input.sizes[batch + dimension] as u64 {
                valid = false;
                input_coords.push(0);
            } else {
                input_coords.push(index as u64);
            }
        }
        for dimension in batch + indexed..input.sizes.len() {
            input_coords.push(output_coords[indices_rank - 1 + dimension - batch - indexed]);
        }
        let value = if valid {
            load_scalar(
                inputs[0],
                index_of(&input_coords, &input.strides),
                input.data_type,
            )
        } else {
            0.0
        };
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            value,
        );
    }
    Ok(())
}

pub(crate) fn execute_scatter_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    axis: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let updates = &plan.inputs[2];
    let count = plan.output.element_count();
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            load_scalar(
                inputs[0],
                index_of(&coords, &input.strides),
                input.data_type,
            ),
        );
    }
    let update_count = indices.element_count();
    for gid in 0..update_count {
        let index_coords = coords_of(gid, &indices.sizes);
        let index = load_integer(
            inputs[1],
            index_of(&index_coords, &indices.strides),
            indices.data_type,
        );
        if index < 0 || index as u64 >= input.sizes[axis as usize] as u64 {
            continue;
        }
        let mut output_coords = index_coords.clone();
        output_coords[axis as usize] = index as u64;
        let output_index = index_of(&output_coords, &plan.output.strides);
        store_scalar(
            output,
            output_index,
            plan.output.data_type,
            load_scalar(
                inputs[2],
                index_of(&index_coords, &updates.strides),
                updates.data_type,
            ),
        );
    }
    Ok(())
}

pub(crate) fn execute_scatter_nd_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    _input_dimension_count: u32,
    _indices_dimension_count: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let updates = &plan.inputs[2];
    let indices_rank = indices.sizes.len();
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let count = plan.output.element_count();
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            load_scalar(
                inputs[0],
                index_of(&coords, &input.strides),
                input.data_type,
            ),
        );
    }
    let update_leading_count: u64 = indices.sizes[..indices_rank - 1]
        .iter()
        .map(|size| *size as u64)
        .product();
    for leading_index in 0..update_leading_count {
        let leading = coords_of(leading_index, &indices.sizes[..indices_rank - 1]);
        let mut output_prefix = Vec::with_capacity(indexed);
        let mut valid = true;
        for dimension in 0..indexed {
            let mut index_coords = leading.clone();
            index_coords.push(dimension as u64);
            let index = load_integer(
                inputs[1],
                index_of(&index_coords, &indices.strides),
                indices.data_type,
            );
            if index < 0 || index as u64 >= input.sizes[dimension] as u64 {
                valid = false;
                break;
            }
            output_prefix.push(index as u64);
        }
        if !valid {
            continue;
        }
        let trailing_sizes = &input.sizes[indexed..];
        let trailing_count: u64 = trailing_sizes.iter().map(|size| *size as u64).product();
        for trailing_index in 0..trailing_count {
            let trailing = coords_of(trailing_index, trailing_sizes);
            let mut output_coords = output_prefix.clone();
            output_coords.extend_from_slice(&trailing);
            let mut update_coords = leading.clone();
            update_coords.extend_from_slice(&trailing);
            store_scalar(
                output,
                index_of(&output_coords, &plan.output.strides),
                plan.output.data_type,
                load_scalar(
                    inputs[2],
                    index_of(&update_coords, &updates.strides),
                    updates.data_type,
                ),
            );
        }
    }
    Ok(())
}
