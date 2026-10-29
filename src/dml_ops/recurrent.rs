//! Recurrent portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_recurrent(
        &self,
        ty: u32,
        direction: DmlRecurrentDirection,
        activations: &[DmlActivation],
        options: DmlRecurrentOptions,
        outputs: &[DmlRecurrentOutput],
        gates: u32,
    ) -> DmlResult<()> {
        let directions = match direction {
            DmlRecurrentDirection::Forward | DmlRecurrentDirection::Backward => 1u32,
            DmlRecurrentDirection::Bidirectional => 2u32,
        };
        let gate_count = gates * directions;
        if self.inputs.len() != options.input_count() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} expects {} input tensor(s), got {}",
                options.input_count(),
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let weight = &self.inputs[1];
        let recurrence = &self.inputs[2];
        if input.sizes.len() != 3 || weight.sizes.len() != 3 || recurrence.sizes.len() != 3 {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} input, weight, and recurrence tensors must be rank 3"
            )));
        }
        let [sequence, batch, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
        if weight.sizes[0] != gate_count {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} weight gate count must be {gate_count}, got {}",
                weight.sizes[0]
            )));
        }
        if weight.sizes[2] != input_size {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} weight input size must be {input_size}, got {}",
                weight.sizes[2]
            )));
        }
        let hidden = weight.sizes[1];
        if hidden == 0 {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} hidden size must be non-zero"
            )));
        }
        if recurrence.sizes != [gate_count, hidden, hidden] {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} recurrence sizes must be [{gate_count}, {hidden}, {hidden}], got {:?}",
                recurrence.sizes
            )));
        }
        let mut slot = 3;
        if options.bias {
            let bias = &self.inputs[slot];
            if bias.element_count() != gate_count as u64 * hidden as u64 || !bias.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} bias must be a contiguous tensor with {} elements",
                    gate_count as u64 * hidden as u64
                )));
            }
            slot += 1;
        }
        if options.hidden_init {
            let hidden_init = &self.inputs[slot];
            if !hidden_init.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} hidden init must be contiguous"
                )));
            }
            if hidden_init.sizes != [1, batch, hidden] {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} hidden init sizes must be [1, {batch}, {hidden}], got {:?}",
                    hidden_init.sizes
                )));
            }
            slot += 1;
        }
        if options.cell_init {
            let cell_init = &self.inputs[slot];
            if !cell_init.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} cell init must be contiguous"
                )));
            }
            if cell_init.sizes != [1, batch, hidden] {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} cell init sizes must be [1, {batch}, {hidden}], got {:?}",
                    cell_init.sizes
                )));
            }
            slot += 1;
        }
        if options.sequence_lengths {
            let lengths = &self.inputs[slot];
            if lengths.element_count() != batch as u64 || !lengths.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} sequence lengths must contain {batch} contiguous elements"
                )));
            }
            slot += 1;
        }
        if options.peephole {
            let peephole = &self.inputs[slot];
            let expected = directions as u64 * 3 * hidden as u64;
            if ty != DML_OPERATOR_LSTM {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} does not accept a peephole tensor"
                )));
            }
            if peephole.element_count() != expected || !peephole.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} peephole tensor must contain {expected} contiguous elements (directions x 3 gates x hidden)"
                )));
            }
        }
        let expected_activations = match ty {
            DML_OPERATOR_RNN => 1..=2,
            DML_OPERATOR_GRU => 2..=2,
            _ => 3..=3,
        };
        if !activations.is_empty() && !expected_activations.contains(&activations.len()) {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} expects {} activation descriptor(s), got {}",
                expected_activations.start(),
                activations.len()
            )));
        }
        for activation in activations {
            activation.validate(activation.operator_type())?;
        }
        if outputs.is_empty() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} requires at least one output tensor"
            )));
        }
        if self.output_count() != outputs.len() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} declares {} output role(s) but has {} output tensor(s)",
                outputs.len(),
                self.output_count()
            )));
        }
        let hidden_output = hidden * directions;
        let mut seen = Vec::new();
        for (role, output) in outputs.iter().zip(self.outputs()) {
            if seen.contains(role) {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} output role is declared more than once"
                )));
            }
            seen.push(*role);
            if output.sizes.len() != 3 {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} recurrent outputs must be rank 3"
                )));
            }
            let expected = match role {
                DmlRecurrentOutput::Sequence => [sequence, batch, hidden_output],
                DmlRecurrentOutput::Single | DmlRecurrentOutput::CellSingle => {
                    [1, batch, hidden_output]
                }
            };
            if output.sizes != expected {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} output sizes must be {expected:?}, got {:?}",
                    output.sizes
                )));
            }
        }
        if ty == DML_OPERATOR_LSTM
            && seen.contains(&DmlRecurrentOutput::CellSingle)
            && !seen.contains(&DmlRecurrentOutput::Single)
        {
            return Err(DmlError::invalid(
                "LSTM cell state output requires a single output tensor",
            ));
        }
        if !seen.contains(&DmlRecurrentOutput::Single)
            && !seen.contains(&DmlRecurrentOutput::Sequence)
        {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} requires a sequence or single hidden-state output"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RecurrentExtras {
    pub(crate) linear_before_reset: bool,
    pub(crate) clip_threshold: f32,
    pub(crate) use_clip_threshold: bool,
    pub(crate) couple_input_forget: bool,
}

pub(crate) fn recurrent_activation(
    activations: &[DmlActivation],
    index: usize,
    default: DmlActivation,
) -> DmlActivation {
    activations.get(index).copied().unwrap_or(default)
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn emit_recurrent_msl_legacy(
    plan: &DmlOpPlan,
    ty: u32,
    direction: DmlRecurrentDirection,
    activations: &[DmlActivation],
    options: DmlRecurrentOptions,
    outputs: &[DmlRecurrentOutput],
    extras: RecurrentExtras,
) -> DmlResult<String> {
    let _ = direction;
    let input = &plan.inputs[0];
    let weight = &plan.inputs[1];
    let recurrence = &plan.inputs[2];
    let [sequence, batch_size, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
    let hidden = weight.sizes[1];
    let hidden_usize = hidden as usize;
    let scalars = vec!["float"; plan.output_count()];
    let mut source = msl_header_outputs(plan, "float", &scalars);
    source.push_str("    uint b = gid;\n");
    source.push_str(&format!(
        "    if (b >= {batch_size}u) return;\n    uint hidden = {hidden}u;\n"
    ));
    source.push_str(&format!(
        "    uint h0 = b * hidden;\n    uint h1 = ({batch_size}u + b) * hidden;\n    uint c0 = (2u * {batch_size}u + b) * hidden;\n    uint gate_base = (3u * {batch_size}u) * hidden + b * hidden * 4u;\n"
    ));
    let bias_index = if options.bias { Some(3) } else { None };
    let hidden_init_index = 3 + usize::from(options.bias);
    let cell_init_index = hidden_init_index + usize::from(options.hidden_init);
    let sequence_lengths_index = cell_init_index + usize::from(options.cell_init);

    source.push_str("    for (uint j = 0u; j < hidden; ++j) {\n");
    if options.hidden_init {
        source.push_str(&format!(
            "        scratch[h0 + j] = float(in{hidden_init_index}[b * hidden + j]);\n"
        ));
    } else {
        source.push_str("        scratch[h0 + j] = 0.0f;\n");
    }
    if options.cell_init {
        source.push_str(&format!(
            "        scratch[c0 + j] = float(in{cell_init_index}[b * hidden + j]);\n"
        ));
    } else {
        source.push_str("        scratch[c0 + j] = 0.0f;\n");
    }
    source.push_str("    }\n");
    if options.sequence_lengths {
        source.push_str(&format!(
            "    uint t_end = min({sequence}u, uint(max(int(in{sequence_lengths_index}[b]), 0)));\n"
        ));
    } else {
        source.push_str(&format!("    uint t_end = {sequence}u;\n"));
    }
    let sequence_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::Sequence)
        .map(|index| format!("out{index}"));
    let single_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::Single)
        .map(|index| format!("out{index}"));
    let cell_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::CellSingle)
        .map(|index| format!("out{index}"));
    source.push_str(&format!("    for (uint t = 0u; t < {sequence}u; ++t) {{\n"));
    source.push_str("        if (t < t_end) {\n");
    match ty {
        DML_OPERATOR_RNN => {
            let activation = recurrent_activation(activations, 0, DmlActivation::Tanh);
            source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str(&format!(
                "                float sum = 0.0f;\n                for (uint i = 0u; i < {input_size}u; ++i) sum += float(in0[(t * {batch_size}u + b) * {input_size}u + i]) * float(in1[j * {}u + i * {}u]);\n",
                weight.strides[1], weight.strides[2]
            ));
            source.push_str(&format!(
                "                for (uint i = 0u; i < hidden; ++i) sum += scratch[h0 + i] * float(in2[j * {}u + i * {}u]);\n",
                recurrence.strides[1], recurrence.strides[2]
            ));
            if let Some(index) = bias_index {
                source.push_str(&format!("                sum += float(in{index}[j]);\n"));
            }
            source.push_str(&format!(
                "                scratch[h1 + j] = {};\n            }}\n",
                activation_msl(activation, 0.0, "sum")
            ));
        }
        DML_OPERATOR_GRU => {
            let gate_activation = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
            let candidate_activation = recurrent_activation(activations, 1, DmlActivation::Tanh);
            source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str(&format!(
                "                float z = 0.0f, r = 0.0f;\n                for (uint i = 0u; i < {input_size}u; ++i) {{ float xv = float(in0[(t * {batch_size}u + b) * {input_size}u + i]); z += xv * float(in1[j * {}u + i * {}u]); r += xv * float(in1[(hidden + j) * {}u + i * {}u]); }}\n",
                weight.strides[1], weight.strides[2], weight.strides[1], weight.strides[2]
            ));
            source.push_str(&format!(
                "                for (uint i = 0u; i < hidden; ++i) {{ float hv = scratch[h0 + i]; z += hv * float(in2[j * {}u + i * {}u]); r += hv * float(in2[(hidden + j) * {}u + i * {}u]); }}\n",
                recurrence.strides[1], recurrence.strides[2], recurrence.strides[1], recurrence.strides[2]
            ));
            if let Some(index) = bias_index {
                source.push_str(&format!(
                    "                z += float(in{index}[j]); r += float(in{index}[hidden + j]);\n"
                ));
            }
            source.push_str(&format!(
                "                z = {}; r = {};\n                scratch[gate_base + j] = z; scratch[gate_base + hidden + j] = r;\n",
                activation_msl(gate_activation, 0.0, "z"),
                activation_msl(gate_activation, 0.0, "r")
            ));
            source.push_str("            }\n");
            source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str("                float reset = scratch[gate_base + hidden + j];\n");
            source.push_str(&format!(
                "                float candidate = 0.0f;\n                for (uint i = 0u; i < {input_size}u; ++i) candidate += float(in0[(t * {batch_size}u + b) * {input_size}u + i]) * float(in1[(2u * hidden + j) * {}u + i * {}u]);\n",
                weight.strides[1], weight.strides[2]
            ));
            if extras.linear_before_reset {
                source.push_str(&format!(
                    "                for (uint i = 0u; i < hidden; ++i) candidate += scratch[h0 + i] * float(in2[(2u * hidden + j) * {}u + i * {}u]);\n",
                    recurrence.strides[1], recurrence.strides[2]
                ));
                if let Some(index) = bias_index {
                    source.push_str(&format!(
                        "                candidate += float(in{index}[2u * hidden + j]);\n"
                    ));
                }
                source.push_str(&format!(
                    "                candidate = {};\n",
                    activation_msl(candidate_activation, 0.0, "candidate")
                ));
            } else {
                source.push_str(&format!(
                    "                float recurrent = 0.0f;\n                for (uint i = 0u; i < hidden; ++i) recurrent += scratch[h0 + i] * float(in2[(2u * hidden + j) * {}u + i * {}u]);\n",
                    recurrence.strides[1], recurrence.strides[2]
                ));
                if let Some(index) = bias_index {
                    source.push_str(&format!(
                        "                candidate += float(in{index}[2u * hidden + j]);\n"
                    ));
                }
                source.push_str(&format!(
                    "                candidate = {};\n",
                    activation_msl(candidate_activation, 0.0, "candidate + reset * recurrent")
                ));
            }
            source.push_str("                float update = scratch[gate_base + j];\n");
            source.push_str("                scratch[h1 + j] = (1.0f - update) * scratch[h0 + j] + update * candidate;\n            }\n");
        }
        _ => {
            let gate_activation = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
            let cell_activation = recurrent_activation(activations, 1, DmlActivation::Tanh);
            let output_activation = recurrent_activation(activations, 2, DmlActivation::Tanh);
            let gate_names = ["i_gate", "o_gate", "f_gate", "c_gate"];
            source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
            for (gate, name) in gate_names.iter().enumerate() {
                source.push_str(&format!("                float {name} = 0.0f;\n"));
                source.push_str(&format!(
                    "                for (uint i = 0u; i < {input_size}u; ++i) {name} += float(in0[(t * {batch_size}u + b) * {input_size}u + i]) * float(in1[({gate}u * hidden + j) * {}u + i * {}u]);\n",
                    weight.strides[1], weight.strides[2]
                ));
                source.push_str(&format!(
                    "                for (uint i = 0u; i < hidden; ++i) {name} += scratch[h0 + i] * float(in2[({gate}u * hidden + j) * {}u + i * {}u]);\n",
                    recurrence.strides[1], recurrence.strides[2]
                ));
                if let Some(index) = bias_index {
                    source.push_str(&format!(
                        "                {name} += float(in{index}[{}u * hidden + j]);\n",
                        gate
                    ));
                }
            }
            source.push_str(&format!(
                "                i_gate = {};\n                f_gate = {};\n                c_gate = {};\n                o_gate = {};\n",
                activation_msl(gate_activation, 0.0, "i_gate"),
                activation_msl(gate_activation, 0.0, "f_gate"),
                activation_msl(cell_activation, 0.0, "c_gate"),
                activation_msl(gate_activation, 0.0, "o_gate")
            ));
            if extras.couple_input_forget {
                source.push_str("                f_gate = 1.0f - i_gate;\n");
            }
            source.push_str(
                "                float cell = f_gate * scratch[c0 + j] + i_gate * c_gate;\n",
            );
            if extras.use_clip_threshold {
                source.push_str(&format!(
                    "                cell = clamp(cell, -{}, {});\n",
                    msl_float(extras.clip_threshold),
                    msl_float(extras.clip_threshold)
                ));
            }
            source.push_str(&format!(
                "                scratch[gate_base + j] = cell;\n                scratch[h1 + j] = o_gate * {};\n            }}\n",
                activation_msl(output_activation, 0.0, "cell")
            ));
        }
    }
    source.push_str("        } else {\n            for (uint j = 0u; j < hidden; ++j) scratch[h1 + j] = scratch[h0 + j];\n        }\n");
    if let Some(sequence_output) = &sequence_output {
        source.push_str("        for (uint j = 0u; j < hidden; ++j) {\n");
        source.push_str(&format!(
            "            {sequence_output}[(t * {batch_size}u + b) * hidden + j] = scratch[h1 + j];\n"
        ));
        source.push_str("        }\n");
    }
    source.push_str(
        "        for (uint j = 0u; j < hidden; ++j) scratch[h0 + j] = scratch[h1 + j];\n",
    );
    if ty == DML_OPERATOR_LSTM {
        source.push_str("        if (t < t_end) for (uint j = 0u; j < hidden; ++j) scratch[c0 + j] = scratch[gate_base + j];\n");
    }
    source.push_str("    }\n");
    if let Some(single_output) = &single_output {
        source.push_str(&format!(
            "    for (uint j = 0u; j < hidden; ++j) {single_output}[b * hidden + j] = scratch[h0 + j];\n"
        ));
    }
    if let Some(cell_output) = &cell_output {
        source.push_str(&format!(
            "    for (uint j = 0u; j < hidden; ++j) {cell_output}[b * hidden + j] = scratch[c0 + j];\n"
        ));
    }
    let _ = hidden_usize;
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_recurrent_msl(
    plan: &DmlOpPlan,
    ty: u32,
    direction: DmlRecurrentDirection,
    activations: &[DmlActivation],
    options: DmlRecurrentOptions,
    outputs: &[DmlRecurrentOutput],
    extras: RecurrentExtras,
) -> DmlResult<String> {
    let directions = match direction {
        DmlRecurrentDirection::Forward | DmlRecurrentDirection::Backward => 1u32,
        DmlRecurrentDirection::Bidirectional => 2u32,
    };
    let gates = match ty {
        DML_OPERATOR_RNN => 1u32,
        DML_OPERATOR_GRU => 3u32,
        _ => 4u32,
    };
    let input = &plan.inputs[0];
    let weight = &plan.inputs[1];
    let recurrence = &plan.inputs[2];
    let [sequence, batch_size, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
    let hidden = weight.sizes[1];
    let gate_span = gates * hidden;
    let output_scalars = plan
        .outputs()
        .map(|output| msl_scalar(output.data_type, ty))
        .collect::<DmlResult<Vec<_>>>()?;
    let mut source = msl_header_outputs(plan, "float", &output_scalars);
    source.push_str("    uint b = gid;\n");
    source.push_str(&format!(
        "    if (b >= {batch_size}u) return;\n    uint hidden = {hidden}u;\n"
    ));
    source.push_str(&format!(
        "    for (uint dir = 0u; dir < {directions}u; ++dir) {{\n"
    ));
    let scratch_span = 7u64 * batch_size as u64 * hidden as u64;
    source.push_str(&format!("        uint sbase = dir * {scratch_span}u;\n"));
    source.push_str(&format!(
        "        uint h0 = sbase + b * hidden;\n        uint h1 = sbase + ({batch_size}u + b) * hidden;\n        uint c0 = sbase + (2u * {batch_size}u + b) * hidden;\n        uint gb = sbase + 3u * {batch_size}u * hidden + b * hidden * 4u;\n"
    ));
    let bias_index = if options.bias { Some(3) } else { None };
    let hidden_init_index = 3 + usize::from(options.bias);
    let cell_init_index = hidden_init_index + usize::from(options.hidden_init);
    let sequence_lengths_index = cell_init_index + usize::from(options.cell_init);
    let peephole_index = sequence_lengths_index + usize::from(options.sequence_lengths);
    source.push_str("        for (uint j = 0u; j < hidden; ++j) {\n");
    if options.hidden_init {
        let desc = &plan.inputs[hidden_init_index];
        source.push_str(&format!(
            "            scratch[h0 + j] = float(in{hidden_init_index}[b * {}u + j * {}u]);\n",
            desc.strides[1], desc.strides[2]
        ));
    } else {
        source.push_str("            scratch[h0 + j] = 0.0f;\n");
    }
    if options.cell_init {
        let desc = &plan.inputs[cell_init_index];
        source.push_str(&format!(
            "            scratch[c0 + j] = float(in{cell_init_index}[b * {}u + j * {}u]);\n",
            desc.strides[1], desc.strides[2]
        ));
    } else {
        source.push_str("            scratch[c0 + j] = 0.0f;\n");
    }
    source.push_str("        }\n");
    if options.sequence_lengths {
        let desc = &plan.inputs[sequence_lengths_index];
        source.push_str(&format!(
            "        uint t_end = min({sequence}u, uint(max(int(in{sequence_lengths_index}[b * {}u]), 0)));\n",
            desc.strides[0]
        ));
    } else {
        source.push_str(&format!("        uint t_end = {sequence}u;\n"));
    }
    let reverse = match direction {
        DmlRecurrentDirection::Forward => "false",
        DmlRecurrentDirection::Backward => "true",
        DmlRecurrentDirection::Bidirectional => "dir == 1u",
    };
    let sequence_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::Sequence);
    let single_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::Single);
    let cell_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::CellSingle);
    source.push_str(&format!(
        "        for (uint step = 0u; step < {sequence}u; ++step) {{\n"
    ));
    source.push_str(&format!(
        "            uint t = ({reverse}) ? ({sequence}u - 1u - step) : step;\n"
    ));
    source.push_str("            if (t < t_end) {\n");
    let weight_index = |gate: u32| {
        format!(
            "in1[((dir * {gate_span}u + {}u + j) * {}u + i * {}u)]",
            gate * hidden,
            weight.strides[0],
            weight.strides[2]
        )
    };
    let recurrence_index = |gate: u32| {
        format!(
            "in2[((dir * {gate_span}u + {}u + j) * {}u + i * {}u)]",
            gate * hidden,
            recurrence.strides[0],
            recurrence.strides[2]
        )
    };
    let bias_index_expr = |gate: u32| {
        bias_index.map(|index| {
            format!(
                "float(in{index}[dir * {gate_span}u + {}u + j])",
                gate * hidden
            )
        })
    };
    let input_index = format!(
        "in0[t * {}u + b * {}u + i * {}u]",
        input.strides[0], input.strides[1], input.strides[2]
    );
    match ty {
        DML_OPERATOR_RNN => {
            let activation = recurrent_activation(activations, 0, DmlActivation::Tanh);
            source.push_str("                for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str("                    float sum = 0.0f;\n");
            source.push_str(&format!(
                "                    for (uint i = 0u; i < {input_size}u; ++i) sum += float({input_index}) * float({});\n",
                weight_index(0)
            ));
            source.push_str(&format!(
                "                    for (uint i = 0u; i < hidden; ++i) sum += scratch[h0 + i] * float({});\n",
                recurrence_index(0)
            ));
            if let Some(bias) = bias_index_expr(0) {
                source.push_str(&format!("                    sum += {bias};\n"));
            }
            source.push_str(&format!(
                "                    scratch[h1 + j] = {};\n                }}\n",
                activation_msl(activation, 0.0, "sum")
            ));
        }
        DML_OPERATOR_GRU => {
            let gate_activation = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
            let candidate_activation = recurrent_activation(activations, 1, DmlActivation::Tanh);
            source.push_str("                for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str("                    float z = 0.0f, r = 0.0f;\n");
            source.push_str(&format!(
                "                    for (uint i = 0u; i < {input_size}u; ++i) {{ float xv = float({input_index}); z += xv * float({}); r += xv * float({}); }}\n",
                weight_index(0),
                weight_index(1)
            ));
            source.push_str(&format!(
                "                    for (uint i = 0u; i < hidden; ++i) {{ float hv = scratch[h0 + i]; z += hv * float({}); r += hv * float({}); }}\n",
                recurrence_index(0),
                recurrence_index(1)
            ));
            if let (Some(z_bias), Some(r_bias)) = (bias_index_expr(0), bias_index_expr(1)) {
                source.push_str(&format!(
                    "                    z += {z_bias}; r += {r_bias};\n"
                ));
            }
            source.push_str(&format!(
                "                    z = {}; r = {};\n                    scratch[gb + j] = z; scratch[gb + hidden + j] = r;\n",
                activation_msl(gate_activation, 0.0, "z"),
                activation_msl(gate_activation, 0.0, "r")
            ));
            source.push_str("                }\n");
            source.push_str("                for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str("                    float reset = scratch[gb + hidden + j];\n");
            source.push_str("                    float candidate = 0.0f;\n");
            source.push_str(&format!(
                "                    for (uint i = 0u; i < {input_size}u; ++i) candidate += float({input_index}) * float({});\n",
                weight_index(2)
            ));
            source.push_str("                    float recurrent = 0.0f;\n");
            source.push_str(&format!(
                "                    for (uint i = 0u; i < hidden; ++i) recurrent += scratch[h0 + i] * float({});\n",
                recurrence_index(2)
            ));
            if let Some(bias) = bias_index_expr(2) {
                source.push_str(&format!("                    candidate += {bias};\n"));
            }
            let _ = extras.linear_before_reset;
            source.push_str(&format!(
                "                    candidate = {};\n",
                activation_msl(candidate_activation, 0.0, "candidate + reset * recurrent")
            ));
            source.push_str(
                "                    float update = scratch[gb + j];\n                    scratch[h1 + j] = (1.0f - update) * scratch[h0 + j] + update * candidate;\n                }\n",
            );
        }
        _ => {
            let gate_activation = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
            let cell_activation = recurrent_activation(activations, 1, DmlActivation::Tanh);
            let output_activation = recurrent_activation(activations, 2, DmlActivation::Tanh);
            let gate_names = ["i_gate", "o_gate", "f_gate", "c_gate"];
            source.push_str("                for (uint j = 0u; j < hidden; ++j) {\n");
            for (gate, name) in gate_names.iter().enumerate() {
                source.push_str(&format!("                    float {name} = 0.0f;\n"));
                source.push_str(&format!(
                    "                    for (uint i = 0u; i < {input_size}u; ++i) {name} += float({input_index}) * float({});\n",
                    weight_index(gate as u32)
                ));
                source.push_str(&format!(
                    "                    for (uint i = 0u; i < hidden; ++i) {name} += scratch[h0 + i] * float({});\n",
                    recurrence_index(gate as u32)
                ));
                if let Some(bias) = bias_index_expr(gate as u32) {
                    source.push_str(&format!("                    {name} += {bias};\n"));
                }
            }
            source.push_str(&format!(
                "                    i_gate = {};\n                    o_gate = {};\n                    f_gate = {};\n                    c_gate = {};\n",
                activation_msl(gate_activation, 0.0, "i_gate"),
                activation_msl(gate_activation, 0.0, "o_gate"),
                activation_msl(gate_activation, 0.0, "f_gate"),
                activation_msl(cell_activation, 0.0, "c_gate")
            ));
            if options.peephole {
                source.push_str(&format!(
                    "                    i_gate += float(in{peephole_index}[dir * {}u + j]) * scratch[c0 + j];\n                    f_gate += float(in{peephole_index}[dir * {}u + hidden + j]) * scratch[c0 + j];\n",
                    3 * hidden,
                    3 * hidden
                ));
                source.push_str(&format!(
                    "                    i_gate = {};\n                    f_gate = {};\n",
                    activation_msl(gate_activation, 0.0, "i_gate"),
                    activation_msl(gate_activation, 0.0, "f_gate")
                ));
            }
            if extras.couple_input_forget {
                source.push_str("                    f_gate = 1.0f - i_gate;\n");
            }
            source.push_str(
                "                    float cell = f_gate * scratch[c0 + j] + i_gate * c_gate;\n",
            );
            if extras.use_clip_threshold {
                source.push_str(&format!(
                    "                    cell = clamp(cell, -{}, {});\n",
                    msl_float(extras.clip_threshold),
                    msl_float(extras.clip_threshold)
                ));
            }
            source.push_str("                    scratch[gb + j] = cell;\n");
            if options.peephole {
                source.push_str(&format!(
                    "                    float o_gate_peep = float(in{peephole_index}[dir * {}u + 2u * hidden + j]);\n                    float o_gate_value = {} + o_gate_peep * cell;\n                    scratch[h1 + j] = {} * {};\n",
                    3 * hidden,
                    activation_msl(gate_activation, 0.0, "o_gate"),
                    activation_msl(gate_activation, 0.0, "o_gate_value"),
                    activation_msl(output_activation, 0.0, "cell")
                ));
            } else {
                source.push_str(&format!(
                    "                    scratch[h1 + j] = o_gate * {};\n",
                    activation_msl(output_activation, 0.0, "cell")
                ));
            }
            source.push_str("                }\n");
        }
    }
    source.push_str(
        "            } else {\n                for (uint j = 0u; j < hidden; ++j) scratch[h1 + j] = scratch[h0 + j];\n            }\n",
    );
    if let Some(role) = sequence_output {
        let output = plan.outputs().nth(role).expect("sequence output");
        let scalar = output_scalars[role];
        source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
        source.push_str(&format!(
            "                out{role}[t * {}u + b * {}u + (dir * hidden + j) * {}u] = ({scalar})scratch[h1 + j];\n",
            output.strides[0], output.strides[1], output.strides[2]
        ));
        source.push_str("            }\n");
    }
    source.push_str(
        "            for (uint j = 0u; j < hidden; ++j) scratch[h0 + j] = scratch[h1 + j];\n",
    );
    if ty == DML_OPERATOR_LSTM {
        source.push_str("            if (t < t_end) for (uint j = 0u; j < hidden; ++j) scratch[c0 + j] = scratch[gb + j];\n");
    }
    source.push_str("        }\n");
    for (role, output) in [(single_output, "single"), (cell_output, "cell")] {
        let Some(role) = role else { continue };
        let desc = plan.outputs().nth(role).expect("recurrent output");
        let scalar = output_scalars[role];
        let source_state = if output == "cell" { "c0" } else { "h0" };
        source.push_str("        for (uint j = 0u; j < hidden; ++j) {\n");
        source.push_str(&format!(
            "            out{role}[b * {}u + (dir * hidden + j) * {}u] = ({scalar})scratch[{source_state} + j];\n",
            desc.strides[1], desc.strides[2]
        ));
        source.push_str("        }\n");
    }
    source.push_str("    }\n");
    source.push_str("}\n");
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn execute_recurrent_cpu_legacy(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
    ty: u32,
    direction: DmlRecurrentDirection,
    activations: &[DmlActivation],
    options: DmlRecurrentOptions,
    roles: &[DmlRecurrentOutput],
    extras: RecurrentExtras,
) -> DmlResult<()> {
    if direction != DmlRecurrentDirection::Forward {
        return Err(DmlError::invalid(format!(
            "DML_OPERATOR_TYPE {ty} only supports DML_RECURRENT_NETWORK_DIRECTION_FORWARD"
        )));
    }
    let input = &plan.inputs[0];
    let weight = &plan.inputs[1];
    let recurrence = &plan.inputs[2];
    let [sequence, batch, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
    let hidden = weight.sizes[1] as usize;
    let batch_usize = batch as usize;
    let input_size_usize = input_size as usize;
    let bias_index = if options.bias { Some(3) } else { None };
    let hidden_init_index = 3 + usize::from(options.bias);
    let cell_init_index = hidden_init_index + usize::from(options.hidden_init);
    let sequence_lengths_index = cell_init_index + usize::from(options.cell_init);
    let sequence_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::Sequence);
    let single_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::Single);
    let cell_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::CellSingle);
    let mut hidden_state = vec![vec![0.0f32; hidden]; batch_usize];
    let mut cell_state = vec![vec![0.0f32; hidden]; batch_usize];
    if options.hidden_init {
        let desc = &plan.inputs[hidden_init_index];
        for b in 0..batch_usize {
            for j in 0..hidden {
                hidden_state[b][j] = load_scalar(
                    inputs[hidden_init_index],
                    index_of(&[0, b as u64, j as u64], &desc.strides),
                    desc.data_type,
                );
            }
        }
    }
    if options.cell_init {
        let desc = &plan.inputs[cell_init_index];
        for b in 0..batch_usize {
            for j in 0..hidden {
                cell_state[b][j] = load_scalar(
                    inputs[cell_init_index],
                    index_of(&[0, b as u64, j as u64], &desc.strides),
                    desc.data_type,
                );
            }
        }
    }
    let gate_activation = recurrent_activation(activations, 0, DmlActivation::Tanh);
    for b in 0..batch_usize {
        let t_end = if options.sequence_lengths {
            let desc = &plan.inputs[sequence_lengths_index];
            load_integer(inputs[sequence_lengths_index], b as u64, desc.data_type)
                .clamp(0, sequence as i64) as u32
        } else {
            sequence
        };
        for t in 0..sequence {
            if t < t_end {
                let mut next = vec![0.0f32; hidden];
                match ty {
                    DML_OPERATOR_RNN => {
                        for j in 0..hidden {
                            let mut sum = 0.0f64;
                            for i in 0..input_size_usize {
                                let x = load_scalar(
                                    inputs[0],
                                    index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                    input.data_type,
                                );
                                let w = load_scalar(
                                    inputs[1],
                                    index_of(&[0, j as u64, i as u64], &weight.strides),
                                    weight.data_type,
                                );
                                sum += x as f64 * w as f64;
                            }
                            for i in 0..hidden {
                                let h = hidden_state[b][i];
                                let r = load_scalar(
                                    inputs[2],
                                    index_of(&[0, j as u64, i as u64], &recurrence.strides),
                                    recurrence.data_type,
                                );
                                sum += h as f64 * r as f64;
                            }
                            if let Some(index) = bias_index {
                                sum += load_scalar(
                                    inputs[index],
                                    (j as u64) as u64,
                                    plan.inputs[index].data_type,
                                ) as f64;
                            }
                            next[j] = activation_cpu(gate_activation, sum as f32);
                        }
                    }
                    DML_OPERATOR_GRU => {
                        let gate = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
                        let candidate_activation =
                            recurrent_activation(activations, 1, DmlActivation::Tanh);
                        let hidden_now = hidden_state[b].clone();
                        let mut z = vec![0.0f32; hidden];
                        let mut r = vec![0.0f32; hidden];
                        for j in 0..hidden {
                            let mut z_sum = 0.0f64;
                            let mut r_sum = 0.0f64;
                            for i in 0..input_size_usize {
                                let x = load_scalar(
                                    inputs[0],
                                    index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                    input.data_type,
                                ) as f64;
                                z_sum += x * load_scalar(
                                    inputs[1],
                                    index_of(&[0, j as u64, i as u64], &weight.strides),
                                    weight.data_type,
                                ) as f64;
                                r_sum += x * load_scalar(
                                    inputs[1],
                                    index_of(&[1, j as u64, i as u64], &weight.strides),
                                    weight.data_type,
                                ) as f64;
                            }
                            for i in 0..hidden {
                                let h = hidden_now[i] as f64;
                                z_sum += h * load_scalar(
                                    inputs[2],
                                    index_of(&[0, j as u64, i as u64], &recurrence.strides),
                                    recurrence.data_type,
                                ) as f64;
                                r_sum += h * load_scalar(
                                    inputs[2],
                                    index_of(&[1, j as u64, i as u64], &recurrence.strides),
                                    recurrence.data_type,
                                ) as f64;
                            }
                            if let Some(index) = bias_index {
                                z_sum += load_scalar(
                                    inputs[index],
                                    j as u64,
                                    plan.inputs[index].data_type,
                                ) as f64;
                                r_sum += load_scalar(
                                    inputs[index],
                                    (hidden + j) as u64,
                                    plan.inputs[index].data_type,
                                ) as f64;
                            }
                            z[j] = activation_cpu(gate, z_sum as f32);
                            r[j] = activation_cpu(gate, r_sum as f32);
                        }
                        for j in 0..hidden {
                            let mut input_term = 0.0f64;
                            for i in 0..input_size_usize {
                                input_term += load_scalar(
                                    inputs[0],
                                    index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                    input.data_type,
                                ) as f64
                                    * load_scalar(
                                        inputs[1],
                                        index_of(&[2, j as u64, i as u64], &weight.strides),
                                        weight.data_type,
                                    ) as f64;
                            }
                            if let Some(index) = bias_index {
                                input_term += load_scalar(
                                    inputs[index],
                                    (2 * hidden + j) as u64,
                                    plan.inputs[index].data_type,
                                ) as f64;
                            }
                            let mut recurrent_term = 0.0f64;
                            for i in 0..hidden {
                                recurrent_term += hidden_state[b][i] as f64
                                    * load_scalar(
                                        inputs[2],
                                        index_of(&[2, j as u64, i as u64], &recurrence.strides),
                                        recurrence.data_type,
                                    ) as f64;
                            }
                            let combined = if extras.linear_before_reset {
                                input_term + r[j] as f64 * recurrent_term
                            } else {
                                input_term + r[j] as f64 * recurrent_term
                            };
                            let candidate = activation_cpu(candidate_activation, combined as f32);
                            next[j] = (1.0 - z[j]) * hidden_state[b][j] + z[j] * candidate;
                        }
                    }
                    _ => {
                        let gate = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
                        let cell_gate = recurrent_activation(activations, 1, DmlActivation::Tanh);
                        let output_activation =
                            recurrent_activation(activations, 2, DmlActivation::Tanh);
                        let hidden_now = hidden_state[b].clone();
                        for j in 0..hidden {
                            let mut sums = [0.0f64; 4];
                            for (gate_index, sum) in sums.iter_mut().enumerate() {
                                for i in 0..input_size_usize {
                                    *sum += load_scalar(
                                        inputs[0],
                                        index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                        input.data_type,
                                    ) as f64
                                        * load_scalar(
                                            inputs[1],
                                            index_of(
                                                &[gate_index as u64, j as u64, i as u64],
                                                &weight.strides,
                                            ),
                                            weight.data_type,
                                        ) as f64;
                                }
                                for i in 0..hidden {
                                    *sum += hidden_now[i] as f64
                                        * load_scalar(
                                            inputs[2],
                                            index_of(
                                                &[gate_index as u64, j as u64, i as u64],
                                                &recurrence.strides,
                                            ),
                                            recurrence.data_type,
                                        ) as f64;
                                }
                                if let Some(index) = bias_index {
                                    *sum += load_scalar(
                                        inputs[index],
                                        (gate_index * hidden + j) as u64,
                                        plan.inputs[index].data_type,
                                    ) as f64;
                                }
                            }
                            let i_gate = activation_cpu(gate, sums[0] as f32);
                            let o_gate = activation_cpu(gate, sums[1] as f32);
                            let mut f_gate = activation_cpu(gate, sums[2] as f32);
                            let c_gate = activation_cpu(cell_gate, sums[3] as f32);
                            if extras.couple_input_forget {
                                f_gate = 1.0 - i_gate;
                            }
                            let mut cell = f_gate * cell_state[b][j] + i_gate * c_gate;
                            if extras.use_clip_threshold {
                                cell = cell.clamp(-extras.clip_threshold, extras.clip_threshold);
                            }
                            cell_state[b][j] = cell;
                            next[j] = o_gate * activation_cpu(output_activation, cell);
                        }
                    }
                }
                hidden_state[b] = next;
            }
            if let Some(role) = sequence_role {
                let desc = &plan.outputs().nth(role).expect("role output").clone();
                for j in 0..hidden {
                    let index = index_of(&[t as u64, b as u64, j as u64], &desc.strides);
                    store_scalar(
                        &mut outputs[role][..],
                        index,
                        desc.data_type,
                        hidden_state[b][j],
                    );
                }
            }
        }
        if let Some(role) = single_role {
            let desc = plan.outputs().nth(role).expect("role output").clone();
            for j in 0..hidden {
                let index = index_of(&[0, b as u64, j as u64], &desc.strides);
                store_scalar(
                    &mut outputs[role][..],
                    index,
                    desc.data_type,
                    hidden_state[b][j],
                );
            }
        }
        if let Some(role) = cell_role {
            let desc = plan.outputs().nth(role).expect("role output").clone();
            for j in 0..hidden {
                let index = index_of(&[0, b as u64, j as u64], &desc.strides);
                store_scalar(
                    &mut outputs[role][..],
                    index,
                    desc.data_type,
                    cell_state[b][j],
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn execute_recurrent_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
    ty: u32,
    direction: DmlRecurrentDirection,
    activations: &[DmlActivation],
    options: DmlRecurrentOptions,
    roles: &[DmlRecurrentOutput],
    extras: RecurrentExtras,
) -> DmlResult<()> {
    let directions = match direction {
        DmlRecurrentDirection::Forward | DmlRecurrentDirection::Backward => 1u32,
        DmlRecurrentDirection::Bidirectional => 2u32,
    };
    let gates = match ty {
        DML_OPERATOR_RNN => 1u32,
        DML_OPERATOR_GRU => 3u32,
        _ => 4u32,
    };
    let input = &plan.inputs[0];
    let weight = &plan.inputs[1];
    let recurrence = &plan.inputs[2];
    let [sequence, batch, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
    let hidden = weight.sizes[1] as usize;
    let batch_usize = batch as usize;
    let input_size_usize = input_size as usize;
    let gate_span = gates * hidden as u32;
    let bias_index = if options.bias { Some(3) } else { None };
    let hidden_init_index = 3 + usize::from(options.bias);
    let cell_init_index = hidden_init_index + usize::from(options.hidden_init);
    let sequence_lengths_index = cell_init_index + usize::from(options.cell_init);
    let peephole_index = sequence_lengths_index + usize::from(options.sequence_lengths);
    let sequence_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::Sequence);
    let single_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::Single);
    let cell_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::CellSingle);
    for dir in 0..directions {
        let reverse = match direction {
            DmlRecurrentDirection::Forward => false,
            DmlRecurrentDirection::Backward => true,
            DmlRecurrentDirection::Bidirectional => dir == 1,
        };
        let gate_offset = dir * gate_span;
        let gate_origin = (dir * gates) as u64;
        let mut hidden_state = vec![vec![0.0f32; hidden]; batch_usize];
        let mut cell_state = vec![vec![0.0f32; hidden]; batch_usize];
        if options.hidden_init {
            let desc = &plan.inputs[hidden_init_index];
            for b in 0..batch_usize {
                for j in 0..hidden {
                    hidden_state[b][j] = load_scalar(
                        inputs[hidden_init_index],
                        index_of(&[0, b as u64, j as u64], &desc.strides),
                        desc.data_type,
                    );
                }
            }
        }
        if options.cell_init {
            let desc = &plan.inputs[cell_init_index];
            for b in 0..batch_usize {
                for j in 0..hidden {
                    cell_state[b][j] = load_scalar(
                        inputs[cell_init_index],
                        index_of(&[0, b as u64, j as u64], &desc.strides),
                        desc.data_type,
                    );
                }
            }
        }
        let gate_activation = recurrent_activation(activations, 0, DmlActivation::Tanh);
        for b in 0..batch_usize {
            let t_end = if options.sequence_lengths {
                let desc = &plan.inputs[sequence_lengths_index];
                load_integer(
                    inputs[sequence_lengths_index],
                    index_of(&[b as u64], &desc.strides),
                    desc.data_type,
                )
                .clamp(0, sequence as i64) as u32
            } else {
                sequence
            };
            for step in 0..sequence {
                let t = if reverse { sequence - 1 - step } else { step };
                if t < t_end {
                    let mut next = vec![0.0f32; hidden];
                    match ty {
                        DML_OPERATOR_RNN => {
                            for j in 0..hidden {
                                let mut sum = 0.0f64;
                                for i in 0..input_size_usize {
                                    let x = load_scalar(
                                        inputs[0],
                                        index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                        input.data_type,
                                    );
                                    let w = load_scalar(
                                        inputs[1],
                                        index_of(
                                            &[gate_origin, j as u64, i as u64],
                                            &weight.strides,
                                        ),
                                        weight.data_type,
                                    );
                                    sum += x as f64 * w as f64;
                                }
                                for i in 0..hidden {
                                    let hsv = hidden_state[b][i];
                                    let r = load_scalar(
                                        inputs[2],
                                        index_of(
                                            &[gate_origin, j as u64, i as u64],
                                            &recurrence.strides,
                                        ),
                                        recurrence.data_type,
                                    );
                                    sum += hsv as f64 * r as f64;
                                }
                                if let Some(index) = bias_index {
                                    sum += load_scalar(
                                        inputs[index],
                                        (gate_offset + j as u32) as u64,
                                        plan.inputs[index].data_type,
                                    ) as f64;
                                }
                                next[j] = activation_cpu(gate_activation, sum as f32);
                            }
                        }
                        DML_OPERATOR_GRU => {
                            let gate = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
                            let candidate_activation =
                                recurrent_activation(activations, 1, DmlActivation::Tanh);
                            let hidden_now = hidden_state[b].clone();
                            let mut z = vec![0.0f32; hidden];
                            let mut r = vec![0.0f32; hidden];
                            for j in 0..hidden {
                                let mut z_sum = 0.0f64;
                                let mut r_sum = 0.0f64;
                                for i in 0..input_size_usize {
                                    let x = load_scalar(
                                        inputs[0],
                                        index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                        input.data_type,
                                    ) as f64;
                                    z_sum += x * load_scalar(
                                        inputs[1],
                                        index_of(
                                            &[gate_origin, j as u64, i as u64],
                                            &weight.strides,
                                        ),
                                        weight.data_type,
                                    ) as f64;
                                    r_sum += x * load_scalar(
                                        inputs[1],
                                        index_of(
                                            &[gate_origin + 1, j as u64, i as u64],
                                            &weight.strides,
                                        ),
                                        weight.data_type,
                                    ) as f64;
                                }
                                for i in 0..hidden {
                                    let hsv = hidden_now[i] as f64;
                                    z_sum += hsv
                                        * load_scalar(
                                            inputs[2],
                                            index_of(
                                                &[gate_origin, j as u64, i as u64],
                                                &recurrence.strides,
                                            ),
                                            recurrence.data_type,
                                        ) as f64;
                                    r_sum += hsv
                                        * load_scalar(
                                            inputs[2],
                                            index_of(
                                                &[gate_origin + 1, j as u64, i as u64],
                                                &recurrence.strides,
                                            ),
                                            recurrence.data_type,
                                        ) as f64;
                                }
                                if let Some(index) = bias_index {
                                    z_sum += load_scalar(
                                        inputs[index],
                                        (gate_offset + j as u32) as u64,
                                        plan.inputs[index].data_type,
                                    ) as f64;
                                    r_sum += load_scalar(
                                        inputs[index],
                                        (gate_offset + hidden as u32 + j as u32) as u64,
                                        plan.inputs[index].data_type,
                                    ) as f64;
                                }
                                z[j] = activation_cpu(gate, z_sum as f32);
                                r[j] = activation_cpu(gate, r_sum as f32);
                            }
                            for j in 0..hidden {
                                let mut input_term = 0.0f64;
                                for i in 0..input_size_usize {
                                    input_term += load_scalar(
                                        inputs[0],
                                        index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                        input.data_type,
                                    ) as f64
                                        * load_scalar(
                                            inputs[1],
                                            index_of(
                                                &[gate_origin + 2, j as u64, i as u64],
                                                &weight.strides,
                                            ),
                                            weight.data_type,
                                        ) as f64;
                                }
                                let mut recurrent_term = 0.0f64;
                                for i in 0..hidden {
                                    recurrent_term += hidden_now[i] as f64
                                        * load_scalar(
                                            inputs[2],
                                            index_of(
                                                &[gate_origin + 2, j as u64, i as u64],
                                                &recurrence.strides,
                                            ),
                                            recurrence.data_type,
                                        ) as f64;
                                }
                                if let Some(index) = bias_index {
                                    input_term += load_scalar(
                                        inputs[index],
                                        (gate_offset + 2 * hidden as u32 + j as u32) as u64,
                                        plan.inputs[index].data_type,
                                    ) as f64;
                                }
                                let combined = input_term + r[j] as f64 * recurrent_term;
                                let candidate =
                                    activation_cpu(candidate_activation, combined as f32);
                                next[j] = (1.0 - z[j]) * hidden_now[j] + z[j] * candidate;
                            }
                        }
                        _ => {
                            let gate = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
                            let cell_gate =
                                recurrent_activation(activations, 1, DmlActivation::Tanh);
                            let output_activation =
                                recurrent_activation(activations, 2, DmlActivation::Tanh);
                            let hidden_now = hidden_state[b].clone();
                            for j in 0..hidden {
                                let mut sums = [0.0f64; 4];
                                for (gate_index, sum) in sums.iter_mut().enumerate() {
                                    let gate_coord = gate_origin + gate_index as u64;
                                    for i in 0..input_size_usize {
                                        *sum += load_scalar(
                                            inputs[0],
                                            index_of(
                                                &[t as u64, b as u64, i as u64],
                                                &input.strides,
                                            ),
                                            input.data_type,
                                        ) as f64
                                            * load_scalar(
                                                inputs[1],
                                                index_of(
                                                    &[gate_coord, j as u64, i as u64],
                                                    &weight.strides,
                                                ),
                                                weight.data_type,
                                            ) as f64;
                                    }
                                    for i in 0..hidden {
                                        *sum += hidden_now[i] as f64
                                            * load_scalar(
                                                inputs[2],
                                                index_of(
                                                    &[gate_coord, j as u64, i as u64],
                                                    &recurrence.strides,
                                                ),
                                                recurrence.data_type,
                                            ) as f64;
                                    }
                                    if let Some(index) = bias_index {
                                        let row = gate_offset
                                            + gate_index as u32 * hidden as u32
                                            + j as u32;
                                        *sum += load_scalar(
                                            inputs[index],
                                            row as u64,
                                            plan.inputs[index].data_type,
                                        ) as f64;
                                    }
                                }
                                let mut i_gate = activation_cpu(gate, sums[0] as f32);
                                let mut f_gate = activation_cpu(gate, sums[2] as f32);
                                let c_gate = activation_cpu(cell_gate, sums[3] as f32);
                                if options.peephole {
                                    let desc = &plan.inputs[peephole_index];
                                    let base = dir as u64 * 3 * hidden as u64;
                                    i_gate += load_scalar(
                                        inputs[peephole_index],
                                        base + j as u64,
                                        desc.data_type,
                                    ) * cell_state[b][j];
                                    f_gate += load_scalar(
                                        inputs[peephole_index],
                                        base + hidden as u64 + j as u64,
                                        desc.data_type,
                                    ) * cell_state[b][j];
                                    i_gate = activation_cpu(gate, i_gate);
                                    f_gate = activation_cpu(gate, f_gate);
                                }
                                if extras.couple_input_forget {
                                    f_gate = 1.0 - i_gate;
                                }
                                let mut cell = f_gate * cell_state[b][j] + i_gate * c_gate;
                                if extras.use_clip_threshold {
                                    cell =
                                        cell.clamp(-extras.clip_threshold, extras.clip_threshold);
                                }
                                cell_state[b][j] = cell;
                                let mut o_gate = activation_cpu(gate, sums[1] as f32);
                                if options.peephole {
                                    let desc = &plan.inputs[peephole_index];
                                    let base = dir as u64 * 3 * hidden as u64;
                                    o_gate += load_scalar(
                                        inputs[peephole_index],
                                        base + 2 * hidden as u64 + j as u64,
                                        desc.data_type,
                                    ) * cell;
                                    o_gate = activation_cpu(gate, o_gate);
                                }
                                next[j] = o_gate * activation_cpu(output_activation, cell);
                            }
                        }
                    }
                    hidden_state[b] = next;
                }
                if let Some(role) = sequence_role {
                    let desc = &plan.outputs().nth(role).expect("role output").clone();
                    for j in 0..hidden {
                        let index = index_of(
                            &[t as u64, b as u64, (dir as usize * hidden + j) as u64],
                            &desc.strides,
                        );
                        store_scalar(
                            &mut outputs[role][..],
                            index,
                            desc.data_type,
                            hidden_state[b][j],
                        );
                    }
                }
            }
            let column_offset = dir as usize * hidden;
            if let Some(role) = single_role {
                let desc = plan.outputs().nth(role).expect("role output").clone();
                for j in 0..hidden {
                    let index = index_of(&[0, b as u64, (column_offset + j) as u64], &desc.strides);
                    store_scalar(
                        &mut outputs[role][..],
                        index,
                        desc.data_type,
                        hidden_state[b][j],
                    );
                }
            }
            if let Some(role) = cell_role {
                let desc = plan.outputs().nth(role).expect("role output").clone();
                for j in 0..hidden {
                    let index = index_of(&[0, b as u64, (column_offset + j) as u64], &desc.strides);
                    store_scalar(
                        &mut outputs[role][..],
                        index,
                        desc.data_type,
                        cell_state[b][j],
                    );
                }
            }
        }
    }
    Ok(())
}
