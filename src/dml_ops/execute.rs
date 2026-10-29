//! Execute portion of the DML operator implementation.

use super::*;

/// Compile the emitted MSL into a real Metal compute pipeline.
pub fn compile_msl(source: &str) -> DmlResult<()> {
    let device = MetalDevice::system_default().map_err(|error| {
        DmlError::unsupported_feature(format!("no Metal device available: {error}"))
    })?;
    let library = device
        .compile_shader_library(source)
        .map_err(|error| DmlError::new(E_FAIL, format!("Metal compilation failed: {error}")))?;
    let function = library
        .get_function("dml_op", None)
        .map_err(|error| DmlError::new(E_FAIL, format!("dml_op function missing: {error}")))?;
    device
        .metal_device()
        .new_compute_pipeline_state_with_function(&function)
        .map_err(|error| DmlError::new(E_FAIL, format!("pipeline creation failed: {error}")))?;
    Ok(())
}

/// Execute a validated operator plan on the selected backend.
pub fn execute_plan(
    plan: &DmlOpPlan,
    backend: DmlExecutionDevice,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    let mut outputs = [output];
    execute_plan_outputs(plan, backend, inputs, &mut outputs)
}

/// Execute a validated operator plan with one buffer per output tensor.
///
/// Multi-output operators (split, top-k, dynamic quantize, recurrent networks,
/// Adam) require exactly [`DmlOpPlan::output_count`] buffers.
pub fn execute_plan_outputs(
    plan: &DmlOpPlan,
    backend: DmlExecutionDevice,
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    plan.validate()?;
    let roles = plan.input_roles();
    if inputs.len() != plan.inputs.len() {
        return Err(DmlError::invalid(format!(
            "operator expects {} input buffers, got {}",
            plan.inputs.len(),
            inputs.len()
        )));
    }
    for (index, (buffer, desc)) in inputs.iter().zip(&plan.inputs).enumerate() {
        let required = desc.total_size_in_bytes as usize;
        if buffer.len() < required {
            return Err(DmlError::invalid(format!(
                "input {} buffer is {} bytes, tensor requires {required}",
                roles[index],
                buffer.len()
            )));
        }
    }
    if outputs.len() != plan.output_count() {
        return Err(DmlError::invalid(format!(
            "operator expects {} output buffers, got {}",
            plan.output_count(),
            outputs.len()
        )));
    }
    let output_roles = plan.output_roles();
    for (index, (output, desc)) in outputs.iter().zip(plan.outputs()).enumerate() {
        let required = desc.total_size_in_bytes as usize;
        if output.len() < required {
            let label = if index == 0 && output_roles[index] == "output" {
                "output".to_string()
            } else {
                format!("output {}", output_roles[index])
            };
            return Err(DmlError::invalid(format!(
                "{label} buffer is {} bytes, tensor requires {required}",
                output.len()
            )));
        }
    }
    match backend {
        DmlExecutionDevice::Metal => execute_metal(plan, inputs, outputs),
        DmlExecutionDevice::Cpu => execute_cpu(plan, inputs, outputs),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum GraphSource {
    Input(usize),
    Node(u32, usize),
}

pub(crate) fn graph_wiring(
    graph: &super::super::DmlGraphPlan,
) -> DmlResult<(
    Vec<Vec<Option<GraphSource>>>,
    Vec<Option<GraphSource>>,
    Vec<u64>,
)> {
    let mut inputs: Vec<Vec<Option<GraphSource>>> = graph
        .nodes
        .iter()
        .map(|node| vec![None; node.inputs.len()])
        .collect();
    for edge in &graph.input_edges {
        let slot = inputs
            .get_mut(edge.to_node as usize)
            .and_then(|node| node.get_mut(edge.to_node_input as usize))
            .ok_or_else(|| {
                DmlError::invalid(format!(
                    "input edge targets node {} input {}, which does not exist",
                    edge.to_node, edge.to_node_input
                ))
            })?;
        *slot = Some(GraphSource::Input(edge.graph_input as usize));
    }
    for edge in &graph.intermediate_edges {
        if edge.from_node as usize >= graph.nodes.len() {
            return Err(DmlError::invalid(format!(
                "intermediate edge references node {}, which does not exist",
                edge.from_node
            )));
        }
        let slot = inputs
            .get_mut(edge.to_node as usize)
            .and_then(|node| node.get_mut(edge.to_node_input as usize))
            .ok_or_else(|| {
                DmlError::invalid(format!(
                    "intermediate edge targets node {} input {}, which does not exist",
                    edge.to_node, edge.to_node_input
                ))
            })?;
        *slot = Some(GraphSource::Node(
            edge.from_node,
            edge.from_node_output as usize,
        ));
    }
    for (node_index, node) in graph.nodes.iter().enumerate() {
        for (input_index, source) in inputs[node_index].iter().enumerate() {
            if source.is_none() {
                return Err(DmlError::invalid(format!(
                    "graph node {node_index} input {input_index} is not connected"
                )));
            }
        }
        for (input_index, desc) in node.inputs.iter().enumerate() {
            if let Some(GraphSource::Node(from_node, from_output)) = inputs[node_index][input_index]
            {
                let source = graph
                    .nodes
                    .get(from_node as usize)
                    .and_then(|node| node.outputs().nth(from_output));
                let Some(source) = source else {
                    return Err(DmlError::invalid(format!(
                        "graph edge references node {from_node} output {from_output}, which does not exist"
                    )));
                };
                if source.total_size_in_bytes < desc.total_size_in_bytes {
                    return Err(DmlError::invalid(format!(
                        "graph node {node_index} input {input_index} requires {} bytes but node {from_node} output {from_output} provides {}",
                        desc.total_size_in_bytes, source.total_size_in_bytes
                    )));
                }
            }
        }
    }
    let mut outputs = vec![None; graph.output_count as usize];
    for edge in &graph.output_edges {
        if edge.graph_output as usize >= outputs.len() {
            return Err(DmlError::invalid(format!(
                "graph output {} is out of range",
                edge.graph_output
            )));
        }
        let exists = graph
            .nodes
            .get(edge.from_node as usize)
            .and_then(|node| node.outputs().nth(edge.from_node_output as usize))
            .is_some();
        if !exists {
            return Err(DmlError::invalid(format!(
                "output edge references node {} output {}, which does not exist",
                edge.from_node, edge.from_node_output
            )));
        }
        outputs[edge.graph_output as usize] = Some(GraphSource::Node(
            edge.from_node,
            edge.from_node_output as usize,
        ));
    }
    for (index, source) in outputs.iter().enumerate() {
        if source.is_none() {
            return Err(DmlError::invalid(format!(
                "graph output {index} is not connected"
            )));
        }
    }
    let mut input_sizes = vec![0u64; graph.input_count as usize];
    for (node_index, node) in graph.nodes.iter().enumerate() {
        for (input_index, source) in inputs[node_index].iter().enumerate() {
            if let Some(GraphSource::Input(index)) = source {
                input_sizes[*index] =
                    input_sizes[*index].max(node.inputs[input_index].total_size_in_bytes);
            }
        }
    }
    for (index, size) in input_sizes.iter().enumerate() {
        if *size == 0 {
            return Err(DmlError::invalid(format!(
                "graph input {index} is not connected"
            )));
        }
    }
    Ok((inputs, outputs, input_sizes))
}

/// Execute a validated DirectML graph. Nodes run in topological order; the
/// Metal backend compiles every node into one MSL library and records all
/// kernels on a single command buffer, wiring node outputs directly into
/// downstream input buffers (no host round-trip between nodes).
pub fn execute_graph_plan(
    graph: &super::super::DmlGraphPlan,
    backend: DmlExecutionDevice,
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    let (wiring, output_sources, input_sizes) = graph_wiring(graph)?;
    let mut seen = vec![false; graph.nodes.len()];
    for node in &graph.execution_order {
        let Some(flag) = seen.get_mut(*node as usize) else {
            return Err(DmlError::invalid(format!(
                "graph execution order references node {node}, which does not exist"
            )));
        };
        if *flag {
            return Err(DmlError::invalid(format!(
                "graph execution order contains node {node} more than once"
            )));
        }
        *flag = true;
    }
    if let Some(index) = seen.iter().position(|value| !value) {
        return Err(DmlError::invalid(format!(
            "graph execution order does not include node {index}"
        )));
    }
    if inputs.len() != graph.input_count as usize {
        return Err(DmlError::invalid(format!(
            "graph expects {} input buffers, got {}",
            graph.input_count,
            inputs.len()
        )));
    }
    if outputs.len() != graph.output_count as usize {
        return Err(DmlError::invalid(format!(
            "graph expects {} output buffers, got {}",
            graph.output_count,
            outputs.len()
        )));
    }
    for (index, (buffer, size)) in inputs.iter().zip(&input_sizes).enumerate() {
        if buffer.len() < *size as usize {
            return Err(DmlError::invalid(format!(
                "graph input {index} buffer is {} bytes, graph requires {size}",
                buffer.len()
            )));
        }
    }
    for (index, (buffer, source)) in outputs.iter().zip(&output_sources).enumerate() {
        let Some(GraphSource::Node(node, output)) = source else {
            return Err(DmlError::invalid(format!(
                "graph output {index} has no source"
            )));
        };
        let desc = graph.nodes[*node as usize]
            .outputs()
            .nth(*output)
            .ok_or_else(|| DmlError::invalid("graph output source is missing"))?;
        if buffer.len() < desc.total_size_in_bytes as usize {
            return Err(DmlError::invalid(format!(
                "graph output {index} buffer is {} bytes, graph requires {}",
                buffer.len(),
                desc.total_size_in_bytes
            )));
        }
    }
    match backend {
        DmlExecutionDevice::Cpu => {
            execute_graph_cpu(graph, &wiring, &output_sources, inputs, outputs)
        }
        DmlExecutionDevice::Metal => {
            execute_graph_metal(graph, &wiring, &output_sources, inputs, outputs)
        }
    }
}

pub(crate) fn execute_graph_cpu(
    graph: &super::super::DmlGraphPlan,
    wiring: &[Vec<Option<GraphSource>>],
    output_sources: &[Option<GraphSource>],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    let mut produced: std::collections::BTreeMap<(u32, usize), Vec<u8>> =
        std::collections::BTreeMap::new();
    for node_index in &graph.execution_order {
        let node = &graph.nodes[*node_index as usize];
        let input_buffers: Vec<&[u8]> = wiring[*node_index as usize]
            .iter()
            .map(|source| match source.expect("graph wiring validated") {
                GraphSource::Input(index) => Ok(inputs[index]),
                GraphSource::Node(node, output) => produced
                    .get(&(node, output))
                    .map(|buffer| buffer.as_slice())
                    .ok_or_else(|| {
                        DmlError::invalid(format!(
                            "graph node {node} output {output} is not available"
                        ))
                    }),
            })
            .collect::<DmlResult<Vec<_>>>()?;
        let mut node_outputs: Vec<Vec<u8>> = node
            .outputs()
            .map(|desc| vec![0u8; desc.total_size_in_bytes as usize])
            .collect();
        {
            let mut slices: Vec<&mut [u8]> = node_outputs
                .iter_mut()
                .map(|buffer| buffer.as_mut_slice())
                .collect();
            execute_plan_outputs(node, DmlExecutionDevice::Cpu, &input_buffers, &mut slices)?;
        }
        for (output, buffer) in node_outputs.into_iter().enumerate() {
            produced.insert((*node_index, output), buffer);
        }
    }
    for (index, source) in output_sources.iter().enumerate() {
        let Some(GraphSource::Node(node, output)) = source else {
            return Err(DmlError::invalid("graph output source is missing"));
        };
        let buffer = produced
            .get(&(*node, *output))
            .ok_or_else(|| DmlError::invalid("graph output was not produced"))?;
        outputs[index][..buffer.len()].copy_from_slice(buffer);
    }
    Ok(())
}

/// Whether a node can participate in a cross-node elementwise fusion.
///
/// Fusion is deliberately limited to FLOAT32 single-output element-wise nodes
/// with identical output shapes. That guarantees the fused kernel performs the
/// exact same float arithmetic as the wired per-node kernels (no intermediate
/// half rounding), while the wired path remains the fallback for everything
/// else.
pub(crate) fn fusion_candidate(node: &DmlOpPlan, sizes: &[u32]) -> bool {
    if node.output.data_type != DML_TENSOR_DATA_TYPE_FLOAT32
        || !node.extra_outputs.is_empty()
        || node.output.sizes != sizes
        || node.fused_activation.is_some()
    {
        return false;
    }
    if node.inputs.iter().any(|desc| {
        desc.data_type != DML_TENSOR_DATA_TYPE_FLOAT32
            || desc.sizes.len() != sizes.len()
            || desc
                .sizes
                .iter()
                .zip(sizes)
                .any(|(input, output)| *input != *output && *input != 1)
    }) {
        return false;
    }
    matches!(
        node.kind,
        DmlOpKind::Activation { .. }
            | DmlOpKind::Unary { .. }
            | DmlOpKind::Binary { .. }
            | DmlOpKind::Add1
    )
}

/// Build the graph input slot list and emit one MSL kernel for a fused chain.
pub(crate) fn emit_fused_chain_msl(
    name: &str,
    graph: &super::super::DmlGraphPlan,
    wiring: &[Vec<Option<GraphSource>>],
    nodes: &[usize],
) -> DmlResult<(String, Vec<usize>)> {
    let root = &graph.nodes[nodes[0]];
    let sizes = root.output.sizes.clone();
    let mut used_inputs: Vec<usize> = Vec::new();
    let mut source = String::from("#include <metal_stdlib>\nusing namespace metal;\n");
    source.push_str(&format!("kernel void {name}("));
    // The input list is discovered while emitting, so emit the body first into
    // a temporary buffer and prepend the signature afterwards.
    let mut body = String::new();
    let count = root.output.element_count();
    body.push_str(&format!("    if (gid >= {count}u) return;\n"));
    for (index, size) in sizes.iter().enumerate() {
        let divisor: u64 = sizes[index + 1..]
            .iter()
            .map(|value| *value as u64)
            .product();
        body.push_str(&format!(
            "    uint o{index} = (gid / {divisor}u) % {size}u;\n"
        ));
    }
    let register_input = |graph_input: usize, used_inputs: &mut Vec<usize>| -> usize {
        if let Some(slot) = used_inputs.iter().position(|value| *value == graph_input) {
            slot
        } else {
            used_inputs.push(graph_input);
            used_inputs.len() - 1
        }
    };
    let mut value_name: Option<String> = None;
    for (step, node_index) in nodes.iter().enumerate() {
        let node = &graph.nodes[*node_index];
        let previous = value_name.clone();
        let load = |input_index: usize, used_inputs: &mut Vec<usize>| -> DmlResult<String> {
            match wiring[*node_index][input_index].expect("graph wiring validated") {
                GraphSource::Input(graph_input) => {
                    let slot = register_input(graph_input, used_inputs);
                    Ok(msl_load_float(
                        &node.inputs[input_index],
                        &format!("in{slot}"),
                        &broadcast_index(&node.inputs[input_index]),
                    ))
                }
                GraphSource::Node(node_id, _) => {
                    if step > 0 && node_id as usize == nodes[step - 1] {
                        Ok(previous.clone().expect("previous value"))
                    } else {
                        Err(DmlError::invalid(format!(
                            "fused graph node {node_index} has a non-fusable input"
                        )))
                    }
                }
            }
        };
        let value = match &node.kind {
            DmlOpKind::Activation { activation, alpha } => {
                let input = load(0, &mut used_inputs)?;
                format!(
                    "    float v{step} = {};\n",
                    activation_msl(*activation, *alpha, &format!("({input})"))
                )
            }
            DmlOpKind::Unary { op } => {
                let input = load(0, &mut used_inputs)?;
                format!(
                    "    float v{step} = {};\n",
                    unary_msl(*op, &format!("({input})"))
                )
            }
            DmlOpKind::Binary { op } => {
                let left = load(0, &mut used_inputs)?;
                let right = load(1, &mut used_inputs)?;
                format!(
                    "    float v{step};\n    {{\n        float fa{step} = {left};\n        float fb{step} = {right};\n        float a = fa{step};\n        float b = fb{step};\n        v{step} = ({});\n    }}\n",
                    emit_scalar_binary(*op)
                )
            }
            DmlOpKind::Add1 => {
                let left = load(0, &mut used_inputs)?;
                let right = load(1, &mut used_inputs)?;
                format!(
                    "    float v{step};\n    {{\n        float fa{step} = {left};\n        float fb{step} = {right};\n        float a = fa{step};\n        float b = fb{step};\n        v{step} = (a + b);\n    }}\n"
                )
            }
            _ => {
                return Err(DmlError::invalid(
                    "node is not a fusable element-wise operator",
                ));
            }
        };
        body.push_str(&value);
        value_name = Some(format!("v{step}"));
    }
    for (slot, _) in used_inputs.iter().enumerate() {
        source.push_str(&format!(
            "device const float* in{slot} [[buffer({slot})]], "
        ));
    }
    source.push_str(&format!(
        "device float* out [[buffer({})]], uint gid [[thread_position_in_grid]]) {{\n",
        used_inputs.len()
    ));
    source.push_str(&body);
    let last = value_name.expect("fused chain non-empty");
    source.push_str(&format!(
        "    out[{}] = {last};\n",
        output_index_expr(&root.output)
    ));
    source.push_str("}\n");
    Ok((source, used_inputs))
}

/// Select maximal single-consumer element-wise chains.
pub(crate) fn find_fusion_chains(
    graph: &super::super::DmlGraphPlan,
    wiring: &[Vec<Option<GraphSource>>],
    output_sources: &[Option<GraphSource>],
) -> Vec<Vec<usize>> {
    let mut consumers: std::collections::BTreeMap<(usize, usize), Vec<(usize, usize)>> =
        std::collections::BTreeMap::new();
    let mut graph_outputs = std::collections::BTreeSet::new();
    for (node_index, inputs) in wiring.iter().enumerate() {
        for (input_index, source) in inputs.iter().enumerate() {
            if let Some(GraphSource::Node(node, output)) = source {
                consumers
                    .entry((*node as usize, *output))
                    .or_default()
                    .push((node_index, input_index));
            }
        }
    }
    for source in output_sources.iter().flatten() {
        if let GraphSource::Node(node, output) = source {
            graph_outputs.insert((*node as usize, *output));
        }
    }
    let mut fused = std::collections::BTreeSet::new();
    let mut chains = Vec::new();
    for node_index in &graph.execution_order {
        let index = *node_index as usize;
        if fused.contains(&index) {
            continue;
        }
        let sizes = graph.nodes[index].output.sizes.clone();
        if !fusion_candidate(&graph.nodes[index], &sizes)
            || wiring[index]
                .iter()
                .any(|source| !matches!(source, Some(GraphSource::Input(_))))
        {
            continue;
        }
        let mut chain = vec![index];
        loop {
            let last = *chain.last().expect("chain");
            if graph_outputs.contains(&(last, 0)) {
                break;
            }
            let Some(next) = consumers.get(&(last, 0)) else {
                break;
            };
            if next.len() != 1 {
                break;
            }
            let (next_node, _next_input) = next[0];
            if fused.contains(&next_node)
                || chain.contains(&next_node)
                || !fusion_candidate(&graph.nodes[next_node], &sizes)
            {
                break;
            }
            // Every other input must be a graph input; the chain link must be
            // wired into the candidate node.
            let mut saw_link = false;
            let mut ok = true;
            for source in &wiring[next_node] {
                match source.expect("graph wiring validated") {
                    GraphSource::Input(_) => {}
                    GraphSource::Node(node, output) => {
                        if node as usize == last && output == 0 {
                            saw_link = true;
                        } else {
                            ok = false;
                        }
                    }
                }
            }
            if !ok || !saw_link {
                break;
            }
            chain.push(next_node);
        }
        if chain.len() >= 2 {
            for node in &chain {
                fused.insert(*node);
            }
            chains.push(chain);
        }
    }
    chains
}

pub(crate) fn execute_graph_metal(
    graph: &super::super::DmlGraphPlan,
    wiring: &[Vec<Option<GraphSource>>],
    output_sources: &[Option<GraphSource>],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    let device = MetalDevice::system_default().map_err(|error| {
        DmlError::unsupported_feature(format!("no Metal device available: {error}"))
    })?;
    let chains = find_fusion_chains(graph, wiring, output_sources);
    let mut chain_of = vec![None; graph.nodes.len()];
    let mut fused_sources = Vec::with_capacity(chains.len());
    for (chain_index, chain) in chains.iter().enumerate() {
        for node in chain {
            chain_of[*node] = Some(chain_index);
        }
        let (source, used_inputs) =
            emit_fused_chain_msl(&format!("dml_fused{chain_index}"), graph, wiring, chain)?;
        fused_sources.push((source, used_inputs));
    }
    let mut combined = String::new();
    for (source, _) in &fused_sources {
        combined.push_str(source);
    }
    for (index, node) in graph.nodes.iter().enumerate() {
        let source = emit_msl(node)?;
        combined.push_str(&source.replace(
            "kernel void dml_op(",
            &format!("kernel void dml_node{index}("),
        ));
    }
    let library = device.compile_shader_library(&combined).map_err(|error| {
        DmlError::new(E_FAIL, format!("graph Metal compilation failed: {error}"))
    })?;
    let (_, _, input_sizes) = graph_wiring(graph)?;
    let input_buffers: Vec<_> = inputs
        .iter()
        .zip(&input_sizes)
        .map(|(data, size)| {
            device.create_buffer_with_data(
                &data[..*size as usize],
                metal::MTLResourceOptions::StorageModeShared,
            )
        })
        .collect();
    let mut node_buffers: Vec<Vec<metal::Buffer>> = Vec::with_capacity(graph.nodes.len());
    for node in &graph.nodes {
        node_buffers.push(
            node.outputs()
                .map(|desc| {
                    device.create_buffer(
                        desc.total_size_in_bytes,
                        metal::MTLResourceOptions::StorageModeShared,
                    )
                })
                .collect(),
        );
    }
    let mut scratch_buffers: Vec<Option<metal::Buffer>> = Vec::with_capacity(graph.nodes.len());
    for node in &graph.nodes {
        let scratch = match &node.kind {
            DmlOpKind::Rnn { direction, .. }
            | DmlOpKind::Gru { direction, .. }
            | DmlOpKind::Lstm { direction, .. } => {
                let batch = node.inputs[0].sizes[1] as u64;
                let hidden = node.inputs[1].sizes[1] as u64;
                let directions = if *direction == DmlRecurrentDirection::Bidirectional {
                    2
                } else {
                    1
                };
                Some(device.create_buffer(
                    batch * hidden * 7 * 4 * directions,
                    metal::MTLResourceOptions::StorageModeShared,
                ))
            }
            _ => None,
        };
        scratch_buffers.push(scratch);
    }
    let queue = device.create_command_queue();
    let command_buffer = queue.new_command_buffer();
    {
        let encoder = command_buffer.new_compute_command_encoder();
        for node_index in &graph.execution_order {
            let index = *node_index as usize;
            if let Some(chain_index) = chain_of[index] {
                let chain = &chains[chain_index];
                if chain.last() == Some(&index) {
                    let (_, used_inputs) = &fused_sources[chain_index];
                    let function = library
                        .get_function(&format!("dml_fused{chain_index}"), None)
                        .map_err(|error| {
                            DmlError::new(
                                E_FAIL,
                                format!("dml_fused{chain_index} not found: {error}"),
                            )
                        })?;
                    let pipeline = device
                        .metal_device()
                        .new_compute_pipeline_state_with_function(&function)
                        .map_err(|error| {
                            DmlError::new(E_FAIL, format!("pipeline creation failed: {error}"))
                        })?;
                    encoder.set_compute_pipeline_state(&pipeline);
                    for (slot, graph_input) in used_inputs.iter().enumerate() {
                        encoder.set_buffer(slot as u64, Some(&input_buffers[*graph_input]), 0);
                    }
                    encoder.set_buffer(used_inputs.len() as u64, Some(&node_buffers[index][0]), 0);
                    let count = graph.nodes[index].output.element_count();
                    let max_threads = pipeline.max_total_threads_per_threadgroup();
                    let threadgroup = max_threads.clamp(1, 256);
                    encoder.dispatch_threads(
                        metal::MTLSize::new(count.max(1), 1, 1),
                        metal::MTLSize::new(threadgroup, 1, 1),
                    );
                }
                continue;
            }
            let node = &graph.nodes[index];
            let function = library
                .get_function(&format!("dml_node{index}"), None)
                .map_err(|error| {
                    DmlError::new(E_FAIL, format!("dml_node{index} not found: {error}"))
                })?;
            let pipeline = device
                .metal_device()
                .new_compute_pipeline_state_with_function(&function)
                .map_err(|error| {
                    DmlError::new(E_FAIL, format!("pipeline creation failed: {error}"))
                })?;
            encoder.set_compute_pipeline_state(&pipeline);
            for (input_index, source) in wiring[index].iter().enumerate() {
                let buffer = match source.expect("graph wiring validated") {
                    GraphSource::Input(graph_input) => &input_buffers[graph_input],
                    GraphSource::Node(node, output) => &node_buffers[node as usize][output],
                };
                encoder.set_buffer(input_index as u64, Some(buffer), 0);
            }
            let output_start = node.inputs.len() as u64;
            for (output_index, buffer) in node_buffers[index].iter().enumerate() {
                encoder.set_buffer(output_start + output_index as u64, Some(buffer), 0);
            }
            if let Some(scratch) = &scratch_buffers[index] {
                encoder.set_buffer(
                    output_start + node_buffers[index].len() as u64,
                    Some(scratch),
                    0,
                );
            }
            let count = node.dispatch_count();
            let max_threads = pipeline.max_total_threads_per_threadgroup();
            let threadgroup = max_threads.clamp(1, 256);
            encoder.dispatch_threads(
                metal::MTLSize::new(count.max(1), 1, 1),
                metal::MTLSize::new(threadgroup, 1, 1),
            );
        }
        encoder.end_encoding();
    }
    command_buffer.commit();
    command_buffer.wait_until_completed();
    if command_buffer.status() == metal::MTLCommandBufferStatus::Error {
        return Err(DmlError::new(
            E_FAIL,
            "Metal command buffer failed while executing the DirectML graph",
        ));
    }
    for (index, source) in output_sources.iter().enumerate() {
        let Some(GraphSource::Node(node, output)) = source else {
            return Err(DmlError::invalid("graph output source is missing"));
        };
        let buffer = &node_buffers[*node as usize][*output];
        let length = buffer.length() as usize;
        let contents =
            unsafe { std::slice::from_raw_parts(buffer.contents() as *const u8, length) };
        outputs[index][..length].copy_from_slice(contents);
    }
    Ok(())
}

pub(crate) fn validate_max_unpooling_indices(plan: &DmlOpPlan, inputs: &[&[u8]]) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let output_count = plan.output.element_count();
    for gid in 0..input.element_count() {
        let coords = coords_of(gid, &input.sizes);
        let index = load_integer(
            inputs[1],
            index_of(&coords, &indices.strides),
            indices.data_type,
        );
        if index < 0 || index as u64 >= output_count {
            return Err(DmlError::invalid(format!(
                "max unpooling index {index} is outside the output element count {output_count}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn execute_metal(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    if matches!(plan.kind, DmlOpKind::MaxUnpooling) {
        validate_max_unpooling_indices(plan, inputs)?;
    }
    let device = MetalDevice::system_default().map_err(|error| {
        DmlError::unsupported_feature(format!("no Metal device available: {error}"))
    })?;
    let source = emit_msl(plan)?;
    let library = device
        .compile_shader_library(&source)
        .map_err(|error| DmlError::new(E_FAIL, error.to_string()))?;
    let function = library
        .get_function("dml_op", None)
        .map_err(|error| DmlError::new(E_FAIL, format!("dml_op not found: {error}")))?;
    let pipeline = device
        .metal_device()
        .new_compute_pipeline_state_with_function(&function)
        .map_err(|error| DmlError::new(E_FAIL, format!("pipeline creation failed: {error}")))?;
    let queue = device.create_command_queue();
    let input_buffers: Vec<_> = inputs
        .iter()
        .zip(&plan.inputs)
        .map(|(data, desc)| {
            let length = desc.total_size_in_bytes as usize;
            device.create_buffer_with_data(
                &data[..length],
                metal::MTLResourceOptions::StorageModeShared,
            )
        })
        .collect();
    let output_buffers: Vec<_> = plan
        .outputs()
        .map(|desc| {
            device.create_buffer(
                desc.total_size_in_bytes,
                metal::MTLResourceOptions::StorageModeShared,
            )
        })
        .collect();
    let scratch_buffer = match &plan.kind {
        DmlOpKind::Rnn { direction, .. }
        | DmlOpKind::Gru { direction, .. }
        | DmlOpKind::Lstm { direction, .. } => {
            let batch = plan.inputs[0].sizes[1] as u64;
            let hidden = plan.inputs[1].sizes[1] as u64;
            let directions = if *direction == DmlRecurrentDirection::Bidirectional {
                2
            } else {
                1
            };
            Some(device.create_buffer(
                batch * hidden * 7 * 4 * directions,
                metal::MTLResourceOptions::StorageModeShared,
            ))
        }
        _ => None,
    };
    let command_buffer = queue.new_command_buffer();
    {
        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&pipeline);
        for (index, buffer) in input_buffers.iter().enumerate() {
            encoder.set_buffer(index as u64, Some(buffer), 0);
        }
        let output_start = input_buffers.len() as u64;
        for (index, buffer) in output_buffers.iter().enumerate() {
            encoder.set_buffer(output_start + index as u64, Some(buffer), 0);
        }
        if let Some(scratch) = &scratch_buffer {
            encoder.set_buffer(output_start + output_buffers.len() as u64, Some(scratch), 0);
        }
        let count = plan.dispatch_count();
        let max_threads = pipeline.max_total_threads_per_threadgroup();
        let threadgroup = max_threads.clamp(1, 256);
        encoder.dispatch_threads(
            metal::MTLSize::new(count, 1, 1),
            metal::MTLSize::new(threadgroup, 1, 1),
        );
        encoder.end_encoding();
    }
    command_buffer.commit();
    command_buffer.wait_until_completed();
    if command_buffer.status() == metal::MTLCommandBufferStatus::Error {
        return Err(DmlError::new(
            E_FAIL,
            "Metal command buffer failed while executing the DirectML operator",
        ));
    }
    for (output, buffer) in outputs.iter_mut().zip(&output_buffers) {
        let length = buffer.length() as usize;
        let contents =
            unsafe { std::slice::from_raw_parts(buffer.contents() as *const u8, length) };
        output[..length].copy_from_slice(contents);
    }
    Ok(())
}

pub(crate) fn execute_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    let (primary, extras) = outputs.split_first_mut().expect("output count validated");
    let output = &mut **primary;
    let dtype = plan.output.data_type;
    let count = plan.output.element_count();
    match &plan.kind {
        DmlOpKind::Gemm {
            trans_a,
            trans_b,
            alpha,
            beta,
        } => {
            let a = &plan.inputs[0];
            let b = &plan.inputs[1];
            let rank = a.sizes.len();
            let k = if *trans_a {
                a.sizes[rank - 2]
            } else {
                a.sizes[rank - 1]
            };
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let batch = coords[..rank - 2].to_vec();
                let m_index = coords[rank - 2];
                let n_index = coords[rank - 1];
                let mut acc = 0.0f64;
                for kk in 0..k as u64 {
                    let mut a_coords = batch.clone();
                    if *trans_a {
                        a_coords.push(kk);
                        a_coords.push(m_index);
                    } else {
                        a_coords.push(m_index);
                        a_coords.push(kk);
                    }
                    let mut b_coords = batch.clone();
                    if *trans_b {
                        b_coords.push(n_index);
                        b_coords.push(kk);
                    } else {
                        b_coords.push(kk);
                        b_coords.push(n_index);
                    }
                    acc += load_scalar(inputs[0], index_of(&a_coords, &a.strides), a.data_type)
                        as f64
                        * load_scalar(inputs[1], index_of(&b_coords, &b.strides), b.data_type)
                            as f64;
                }
                let mut value = *alpha as f64 * acc;
                if plan.inputs.len() == 3 {
                    value += *beta as f64
                        * load_scalar(
                            inputs[2],
                            index_of(&coords, &plan.inputs[2].strides),
                            plan.inputs[2].data_type,
                        ) as f64;
                }
                store_scalar(output, output_index(&plan.output, gid), dtype, value as f32);
            }
        }
        DmlOpKind::Convolution {
            mode,
            strides,
            dilations,
            start_padding,
            group_count,
            ..
        } => {
            let input = &plan.inputs[0];
            let filter = &plan.inputs[1];
            let channels_per_group = input.sizes[1] / group_count;
            let filters_per_group = plan.output.sizes[1] / group_count;
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let [batch, out_channel, oh, ow] = [coords[0], coords[1], coords[2], coords[3]];
                let group = out_channel / filters_per_group as u64;
                let mut acc = 0.0f64;
                for cg in 0..channels_per_group as u64 {
                    for fy in 0..filter.sizes[2] as u64 {
                        let iy = oh as i64 * strides[0] as i64 - start_padding[0] as i64
                            + fy as i64 * dilations[0] as i64;
                        if iy < 0 || iy >= input.sizes[2] as i64 {
                            continue;
                        }
                        for fx in 0..filter.sizes[3] as u64 {
                            let ix = ow as i64 * strides[1] as i64 - start_padding[1] as i64
                                + fx as i64 * dilations[1] as i64;
                            if ix < 0 || ix >= input.sizes[3] as i64 {
                                continue;
                            }
                            let input_coords = [
                                batch,
                                group * channels_per_group as u64 + cg,
                                iy as u64,
                                ix as u64,
                            ];
                            let filter_coords = if *mode == DML_CONVOLUTION_MODE_CONVOLUTION {
                                [
                                    out_channel,
                                    cg,
                                    filter.sizes[2] as u64 - 1 - fy,
                                    filter.sizes[3] as u64 - 1 - fx,
                                ]
                            } else {
                                [out_channel, cg, fy, fx]
                            };
                            acc += load_scalar(
                                inputs[0],
                                index_of(&input_coords, &input.strides),
                                input.data_type,
                            ) as f64
                                * load_scalar(
                                    inputs[1],
                                    index_of(&filter_coords, &filter.strides),
                                    filter.data_type,
                                ) as f64;
                        }
                    }
                }
                if plan.inputs.len() == 3 {
                    acc += load_scalar(inputs[2], out_channel, plan.inputs[2].data_type) as f64;
                }
                store_scalar(output, output_index(&plan.output, gid), dtype, acc as f32);
            }
        }
        DmlOpKind::AveragePooling1 {
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            include_padding,
        } => execute_average_pooling1_cpu(
            plan,
            inputs[0],
            output,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            *include_padding,
        )?,
        DmlOpKind::Pooling {
            kind,
            strides,
            window,
            start_padding,
            include_padding,
            ..
        } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let [batch, channel, oh, ow] = [coords[0], coords[1], coords[2], coords[3]];
                let mut sum = 0.0f64;
                let mut valid = 0u64;
                let mut best = f32::NEG_INFINITY;
                let mut saw_nan = false;
                for wy in 0..window[0] as u64 {
                    let iy = oh as i64 * strides[0] as i64 - start_padding[0] as i64 + wy as i64;
                    if iy < 0 || iy >= input.sizes[2] as i64 {
                        continue;
                    }
                    for wx in 0..window[1] as u64 {
                        let ix =
                            ow as i64 * strides[1] as i64 - start_padding[1] as i64 + wx as i64;
                        if ix < 0 || ix >= input.sizes[3] as i64 {
                            continue;
                        }
                        let input_coords = [batch, channel, iy as u64, ix as u64];
                        let value =
                            load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype);
                        if value.is_nan() {
                            saw_nan = true;
                        }
                        if *kind == DmlPoolingKind::Max {
                            if !value.is_nan() {
                                best = best.max(value);
                            }
                        } else {
                            sum += value as f64;
                        }
                        valid += 1;
                    }
                }
                let value = if *kind == DmlPoolingKind::Max {
                    if saw_nan { f32::NAN } else { best }
                } else if valid == 0 {
                    0.0
                } else if *include_padding {
                    (sum / (window[0] as u64 * window[1] as u64) as f64) as f32
                } else {
                    (sum / valid as f64) as f32
                };
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::Activation { activation, alpha } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                let _ = alpha;
                let value = activation_cpu(*activation, value);
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::BatchNormalization { spatial, epsilon } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let x = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                let parameter_coords: Vec<u64> = if *spatial {
                    coords
                        .iter()
                        .enumerate()
                        .map(|(dimension, coord)| if dimension == 1 { *coord } else { 0 })
                        .collect()
                } else {
                    coords.clone()
                };
                let mean = load_scalar(
                    inputs[1],
                    index_of(&parameter_coords, &plan.inputs[1].strides),
                    dtype,
                );
                let variance = load_scalar(
                    inputs[2],
                    index_of(&parameter_coords, &plan.inputs[2].strides),
                    dtype,
                );
                let scale = load_scalar(
                    inputs[3],
                    index_of(&parameter_coords, &plan.inputs[3].strides),
                    dtype,
                );
                let bias = load_scalar(
                    inputs[4],
                    index_of(&parameter_coords, &plan.inputs[4].strides),
                    dtype,
                );
                let value = (x - mean) * (variance + epsilon).sqrt().recip() * scale + bias;
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::Softmax => {
            let input = &plan.inputs[0];
            let rank = input.sizes.len();
            let axis = input.sizes[rank - 1] as u64;
            let rows = count / axis;
            for row in 0..rows {
                let base_coords = coords_of(row, &input.sizes[..rank - 1]);
                let input_base = index_of(&base_coords, &input.strides[..rank - 1]);
                let mut max_value = f32::NEG_INFINITY;
                for j in 0..axis {
                    let value = load_scalar(
                        inputs[0],
                        input_base + j * input.strides[rank - 1] as u64,
                        dtype,
                    );
                    max_value = max_value.max(value);
                }
                let mut sum = 0.0f64;
                for j in 0..axis {
                    let value = load_scalar(
                        inputs[0],
                        input_base + j * input.strides[rank - 1] as u64,
                        dtype,
                    );
                    sum += ((value - max_value) as f64).exp();
                }
                let mut output_coords = base_coords.clone();
                for j in 0..axis {
                    output_coords.push(j);
                    let output_index = index_of(&output_coords, &plan.output.strides);
                    output_coords.pop();
                    let value = load_scalar(
                        inputs[0],
                        input_base + j * input.strides[rank - 1] as u64,
                        dtype,
                    );
                    store_scalar(
                        output,
                        output_index,
                        dtype,
                        (((value - max_value) as f64).exp() / sum) as f32,
                    );
                }
            }
        }
        DmlOpKind::Binary { op } => {
            let a = &plan.inputs[0];
            let b = &plan.inputs[1];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let mut a_coords = coords.clone();
                let mut b_coords = coords.clone();
                for (dimension, coord) in coords.iter().enumerate() {
                    if a.sizes[dimension] == 1 {
                        a_coords[dimension] = 0;
                    }
                    if b.sizes[dimension] == 1 {
                        b_coords[dimension] = 0;
                    }
                    let _ = coord;
                }
                let left = load_scalar(inputs[0], index_of(&a_coords, &a.strides), a.data_type);
                let right = load_scalar(inputs[1], index_of(&b_coords, &b.strides), b.data_type);
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    apply_binary(*op, left, right),
                );
            }
        }
        DmlOpKind::Reduce { reduce, axes } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let reduction_count: u64 = axes
                    .iter()
                    .map(|axis| input.sizes[*axis as usize] as u64)
                    .product();
                let mut sum = if *reduce == DmlReduceKind::Multiply {
                    1.0f64
                } else {
                    0.0f64
                };
                let mut best = if *reduce == DmlReduceKind::Min {
                    f32::INFINITY
                } else {
                    f32::NEG_INFINITY
                };
                let mut lse = f64::NEG_INFINITY;
                let mut saw_nan = false;
                for reduced in 0..reduction_count {
                    let mut input_coords = coords.clone();
                    let mut remainder = reduced;
                    for axis in axes {
                        let axis = *axis as usize;
                        input_coords[axis] = remainder % input.sizes[axis] as u64;
                        remainder /= input.sizes[axis] as u64;
                    }
                    let value =
                        load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype);
                    if value.is_nan() {
                        saw_nan = true;
                    }
                    match reduce {
                        DmlReduceKind::Sum
                        | DmlReduceKind::Mean
                        | DmlReduceKind::LogSum
                        | DmlReduceKind::LogSumExp => sum += value as f64,
                        DmlReduceKind::Multiply => sum *= value as f64,
                        DmlReduceKind::SumSquare | DmlReduceKind::L2 => {
                            sum += (value as f64) * (value as f64)
                        }
                        DmlReduceKind::L1 => sum += (value as f64).abs(),
                        DmlReduceKind::Max => {
                            if !value.is_nan() {
                                best = best.max(value);
                            }
                        }
                        DmlReduceKind::Min => {
                            if !value.is_nan() {
                                best = best.min(value);
                            }
                        }
                        DmlReduceKind::ArgMin | DmlReduceKind::ArgMax => {
                            return Err(DmlError::invalid(
                                "DML_REDUCE_FUNCTION argmin/argmax is not lowered through DML_OPERATOR_REDUCE",
                            ));
                        }
                    }
                    if *reduce == DmlReduceKind::LogSumExp && !value.is_nan() {
                        let current = value as f64;
                        lse = if lse > current {
                            lse + (current - lse).exp().ln_1p()
                        } else if lse.is_infinite() && lse.is_sign_negative() {
                            current
                        } else {
                            current + (lse - current).exp().ln_1p()
                        };
                    }
                }
                let value = match reduce {
                    DmlReduceKind::Sum => sum as f32,
                    DmlReduceKind::Mean => (sum / reduction_count as f64) as f32,
                    DmlReduceKind::Multiply => sum as f32,
                    DmlReduceKind::SumSquare => sum as f32,
                    DmlReduceKind::L1 => sum as f32,
                    DmlReduceKind::L2 => sum.sqrt() as f32,
                    DmlReduceKind::LogSum => (sum as f32).ln(),
                    DmlReduceKind::LogSumExp => {
                        if saw_nan {
                            f32::NAN
                        } else {
                            lse as f32
                        }
                    }
                    DmlReduceKind::Max => {
                        if saw_nan {
                            f32::NAN
                        } else {
                            best
                        }
                    }
                    DmlReduceKind::Min => {
                        if saw_nan {
                            f32::NAN
                        } else {
                            best
                        }
                    }
                    DmlReduceKind::ArgMin | DmlReduceKind::ArgMax => {
                        return Err(DmlError::invalid(
                            "DML_REDUCE_FUNCTION argmin/argmax is not lowered through DML_OPERATOR_REDUCE",
                        ));
                    }
                };
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::Reshape => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let input_coords = coords_of(gid, &input.sizes);
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype),
                );
            }
        }
        DmlOpKind::Transpose { permutation } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let output_coords = coords_of(gid, &plan.output.sizes);
                let mut input_coords = vec![0u64; permutation.len()];
                for (output_dimension, input_dimension) in permutation.iter().enumerate() {
                    input_coords[*input_dimension as usize] = output_coords[output_dimension];
                }
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype),
                );
            }
        }
        DmlOpKind::Concat { axis } => {
            let axis = *axis as usize;
            let mut offsets = Vec::with_capacity(plan.inputs.len());
            let mut offset = 0u64;
            for input in &plan.inputs {
                offsets.push(offset);
                offset += input.sizes[axis] as u64;
            }
            for gid in 0..count {
                let output_coords = coords_of(gid, &plan.output.sizes);
                let position = output_coords[axis];
                let mut selected = 0;
                for (index, input) in plan.inputs.iter().enumerate() {
                    if position < offsets[index] + input.sizes[axis] as u64 {
                        selected = index;
                        break;
                    }
                }
                let mut input_coords = output_coords.clone();
                input_coords[axis] = position - offsets[selected];
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    load_scalar(
                        inputs[selected],
                        index_of(&input_coords, &plan.inputs[selected].strides),
                        dtype,
                    ),
                );
            }
        }
        DmlOpKind::Slice {
            offsets, strides, ..
        } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let output_coords = coords_of(gid, &plan.output.sizes);
                let input_coords: Vec<u64> = output_coords
                    .iter()
                    .enumerate()
                    .map(|(dimension, coord)| {
                        coord * strides[dimension] as u64 + offsets[dimension] as u64
                    })
                    .collect();
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype),
                );
            }
        }
        DmlOpKind::Add1 => execute_binary_cpu(plan, inputs, output, DmlBinaryOp::Add)?,
        DmlOpKind::Rnn {
            direction,
            activations,
            options,
            outputs: roles,
        } => {
            let mut all: Vec<&mut [u8]> = Vec::with_capacity(1 + extras.len());
            all.push(&mut *output);
            for extra in extras.iter_mut() {
                all.push(&mut **extra);
            }
            execute_recurrent_cpu(
                plan,
                inputs,
                &mut all,
                DML_OPERATOR_RNN,
                *direction,
                activations,
                *options,
                roles,
                RecurrentExtras::default(),
            )?
        }
        DmlOpKind::Gru {
            direction,
            activations,
            options,
            outputs: roles,
            linear_before_reset,
        } => {
            let mut all: Vec<&mut [u8]> = Vec::with_capacity(1 + extras.len());
            all.push(&mut *output);
            for extra in extras.iter_mut() {
                all.push(&mut **extra);
            }
            execute_recurrent_cpu(
                plan,
                inputs,
                &mut all,
                DML_OPERATOR_GRU,
                *direction,
                activations,
                *options,
                roles,
                RecurrentExtras {
                    linear_before_reset: *linear_before_reset,
                    ..RecurrentExtras::default()
                },
            )?
        }
        DmlOpKind::Lstm {
            direction,
            activations,
            options,
            outputs: roles,
            clip_threshold,
            use_clip_threshold,
            couple_input_forget,
        } => {
            let mut all: Vec<&mut [u8]> = Vec::with_capacity(1 + extras.len());
            all.push(&mut *output);
            for extra in extras.iter_mut() {
                all.push(&mut **extra);
            }
            execute_recurrent_cpu(
                plan,
                inputs,
                &mut all,
                DML_OPERATOR_LSTM,
                *direction,
                activations,
                *options,
                roles,
                RecurrentExtras {
                    clip_threshold: *clip_threshold,
                    use_clip_threshold: *use_clip_threshold,
                    couple_input_forget: *couple_input_forget,
                    ..RecurrentExtras::default()
                },
            )?
        }
        DmlOpKind::ArgMin { axes, direction } => {
            execute_arg_reduce_cpu(plan, inputs[0], output, axes, *direction, true)?
        }
        DmlOpKind::ArgMax { axes, direction } => {
            execute_arg_reduce_cpu(plan, inputs[0], output, axes, *direction, false)?
        }
        DmlOpKind::Padding {
            mode,
            start_padding,
            end_padding,
            value,
        } => execute_padding_cpu(
            plan,
            inputs[0],
            output,
            *mode,
            start_padding,
            end_padding,
            *value,
        )?,
        DmlOpKind::Resample {
            mode,
            scales,
            input_offsets,
            output_offsets,
            rounding,
            antialiased,
        } => execute_resample_cpu(
            plan,
            inputs[0],
            output,
            *mode,
            scales,
            input_offsets,
            output_offsets,
            *rounding,
            *antialiased,
        )?,
        DmlOpKind::TopK { axis, k, direction } => execute_top_k_cpu(
            plan,
            inputs[0],
            output,
            &mut *extras[0],
            *axis,
            *k,
            *direction,
        )?,
        DmlOpKind::Tile { repeats } => execute_tile_cpu(plan, inputs[0], output, repeats)?,
        DmlOpKind::Split { axis } => execute_split_cpu(plan, inputs[0], output, extras, *axis)?,
        DmlOpKind::Gather {
            axis,
            index_dimensions,
        } => execute_gather_cpu(plan, inputs, output, *axis, *index_dimensions)?,
        DmlOpKind::GatherElements { axis } => {
            execute_gather_elements_cpu(plan, inputs, output, *axis)?
        }
        DmlOpKind::GatherNd {
            input_dimension_count,
            indices_dimension_count,
            batch_dimension_count,
        } => execute_gather_nd_cpu(
            plan,
            inputs,
            output,
            *input_dimension_count,
            *indices_dimension_count,
            *batch_dimension_count,
        )?,
        DmlOpKind::Scatter { axis } => execute_scatter_cpu(plan, inputs, output, *axis)?,
        DmlOpKind::ScatterNd {
            input_dimension_count,
            indices_dimension_count,
        } => execute_scatter_nd_cpu(
            plan,
            inputs,
            output,
            *input_dimension_count,
            *indices_dimension_count,
        )?,
        DmlOpKind::RoiPooling {
            spatial_scale,
            pooled,
        } => execute_roi_pooling_cpu(plan, inputs, output, *spatial_scale, pooled)?,
        DmlOpKind::RoiAlign {
            reduction,
            mode,
            spatial_scale_x,
            spatial_scale_y,
            input_pixel_offset,
            output_pixel_offset,
            out_of_bounds_value,
            minimum_samples_per_output,
            maximum_samples_per_output,
            align_regions_to_corners,
        } => execute_roi_align_cpu(
            plan,
            inputs,
            output,
            *reduction,
            *mode,
            *spatial_scale_x,
            *spatial_scale_y,
            *input_pixel_offset,
            *output_pixel_offset,
            *out_of_bounds_value,
            *minimum_samples_per_output,
            *maximum_samples_per_output,
            *align_regions_to_corners,
        )?,
        DmlOpKind::LocalResponseNormalization {
            cross_channel,
            local_size,
            alpha,
            beta,
            bias,
        } => execute_lrn_cpu(
            plan,
            inputs[0],
            output,
            *cross_channel,
            *local_size,
            *alpha,
            *beta,
            *bias,
        )?,
        DmlOpKind::MeanVarianceNormalization {
            axes,
            normalize_variance,
            use_mean,
            epsilon,
        } => execute_mvn_cpu(
            plan,
            inputs,
            output,
            axes,
            *normalize_variance,
            *use_mean,
            *epsilon,
        )?,
        DmlOpKind::Adam {
            learning_rate,
            beta1,
            beta2,
            epsilon,
        } => execute_adam_cpu(
            plan,
            inputs,
            output,
            extras,
            *learning_rate,
            *beta1,
            *beta2,
            *epsilon,
        )?,
        DmlOpKind::QuantizeLinear => execute_quantize_linear_cpu(plan, inputs, output, false)?,
        DmlOpKind::DequantizeLinear => execute_quantize_linear_cpu(plan, inputs, output, true)?,
        DmlOpKind::DynamicQuantizeLinear => {
            execute_dynamic_quantize_cpu(plan, inputs[0], output, extras)?
        }
        DmlOpKind::QuantizedLinearAdd { .. } => execute_quantized_add_cpu(plan, inputs, output)?,
        DmlOpKind::MatrixMultiplyInteger { .. } => {
            execute_integer_matmul_cpu(plan, inputs, output)?
        }
        DmlOpKind::ConvolutionInteger { .. } => {
            execute_integer_convolution_cpu(plan, inputs, output)?
        }
        DmlOpKind::QuantizedLinearAveragePooling { .. } => {
            execute_quantized_avg_pool_cpu(plan, inputs, output)?
        }
        DmlOpKind::MatrixMultiplyIntegerToFloat { .. } => {
            execute_integer_matmul_to_float_cpu(plan, inputs, output)?
        }
        DmlOpKind::Quantize { quantization_type } => {
            execute_generic_quantize_cpu(plan, inputs, output, *quantization_type, false)?
        }
        DmlOpKind::Dequantize { quantization_type } => {
            execute_generic_quantize_cpu(plan, inputs, output, *quantization_type, true)?
        }
        DmlOpKind::Unary { op } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let mut input_coords = coords.clone();
                for (dimension, coord) in coords.iter().enumerate() {
                    if input.sizes[dimension] == 1 {
                        input_coords[dimension] = 0;
                    }
                    let _ = coord;
                }
                let value = load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype);
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    unary_cpu(*op, value),
                );
            }
        }
        DmlOpKind::Fill {
            value,
            step,
            sequence,
        } => {
            for gid in 0..count {
                let element = if *sequence {
                    *value + *step * gid as f32
                } else {
                    *value
                };
                store_scalar(output, output_index(&plan.output, gid), dtype, element);
            }
        }
        DmlOpKind::OneHot { axis } => {
            let indices = &plan.inputs[0];
            let on_value = load_scalar(inputs[1], 0, plan.inputs[1].data_type);
            let off_value = load_scalar(inputs[1], 1, plan.inputs[1].data_type);
            let depth = plan.output.sizes[*axis as usize] as i64;
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let mut index_coords = Vec::with_capacity(coords.len() - 1);
                for (dimension, coord) in coords.iter().enumerate() {
                    if dimension != *axis as usize {
                        index_coords.push(*coord);
                    }
                }
                let index = load_scalar(
                    inputs[0],
                    index_of(&index_coords, &indices.strides),
                    indices.data_type,
                ) as i64;
                let on = index >= 0 && index < depth && index == coords[*axis as usize] as i64;
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    if on { on_value } else { off_value },
                );
            }
        }
        DmlOpKind::Cumulative {
            product,
            axis,
            reverse,
            exclusive,
        } => {
            let input = &plan.inputs[0];
            let axis = *axis as usize;
            for gid in 0..count {
                let mut coords = coords_of(gid, &plan.output.sizes);
                let position = coords[axis];
                let size = input.sizes[axis];
                let (start, end) = if *reverse {
                    (position, size as u64)
                } else {
                    (0, position + 1)
                };
                let mut acc = if *product { 1.0f32 } else { 0.0f32 };
                for j in start..end {
                    if *exclusive && j == position {
                        continue;
                    }
                    coords[axis] = j;
                    let value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                    if *product {
                        acc *= value;
                    } else {
                        acc += value;
                    }
                }
                store_scalar(output, output_index(&plan.output, gid), dtype, acc);
            }
        }
        DmlOpKind::Reverse { axis } => {
            let input = &plan.inputs[0];
            let lengths = &plan.inputs[1];
            let axis = *axis as usize;
            for gid in 0..count {
                let mut coords = coords_of(gid, &plan.output.sizes);
                let sequence_coords = &coords[..axis];
                let length = load_scalar(
                    inputs[1],
                    index_of(sequence_coords, &lengths.strides),
                    lengths.data_type,
                ) as u64;
                if coords[axis] < length {
                    coords[axis] = length - 1 - coords[axis];
                }
                let value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::DiagonalMatrix { offset, value } => {
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let selected = coords[1] as i64 - coords[0] as i64 == *offset as i64;
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    if selected { *value } else { 0.0 },
                );
            }
        }
        DmlOpKind::Cast => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &input.sizes);
                let value = load_scalar(
                    inputs[0],
                    index_of(&coords, &input.strides),
                    input.data_type,
                );
                store_cast(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::SoftmaxEx { kind, axes } => {
            execute_softmax_ex_cpu(plan, inputs[0], output, *kind, axes)?
        }
        DmlOpKind::ExActivation { activation } => {
            execute_ex_activation_cpu(plan, inputs, output, *activation)?
        }
        DmlOpKind::If => execute_if_cpu(plan, inputs, output)?,
        DmlOpKind::BitNot => execute_bitwise_cpu(plan, inputs[0], output, false)?,
        DmlOpKind::BitCount => execute_bitwise_cpu(plan, inputs[0], output, true)?,
        DmlOpKind::LpPooling {
            p,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            ..
        } => execute_lp_pooling_cpu(
            plan,
            inputs[0],
            output,
            *p,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
        )?,
        DmlOpKind::LpNormalization { axis, epsilon, p } => {
            execute_lp_normalization_cpu(plan, inputs[0], output, *axis, *epsilon, *p)?
        }
        DmlOpKind::ValueScale2D {
            scale,
            channel_count,
            bias,
        } => execute_value_scale_cpu(plan, inputs[0], output, *scale, *channel_count, bias)?,
        DmlOpKind::SpaceDepth {
            to_depth,
            block_size,
            order,
            ..
        } => execute_space_depth_cpu(plan, inputs[0], output, *to_depth, *block_size, *order)?,
        DmlOpKind::MaxPoolingEx {
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            has_indices,
            ..
        } => execute_max_pooling_ex_cpu(
            plan,
            inputs[0],
            output,
            extras.first_mut().map(|value| &mut **value),
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            *has_indices,
        )?,
        DmlOpKind::MaxUnpooling => execute_max_unpooling_cpu(plan, inputs, output)?,
        DmlOpKind::SliceEx {
            offsets,
            sizes,
            strides,
        } => execute_slice_ex_cpu(plan, inputs[0], output, offsets, sizes, strides)?,
        DmlOpKind::Clip1 {
            min,
            max,
            scale,
            bias,
            has_scale_bias,
        } => execute_clip1_cpu(
            plan,
            inputs[0],
            output,
            *min,
            *max,
            *scale,
            *bias,
            *has_scale_bias,
        )?,
        DmlOpKind::ReluGrad => execute_relu_grad_cpu(plan, inputs, output)?,
        DmlOpKind::AveragePoolingGrad {
            strides,
            window,
            start_padding,
            end_padding,
            include_padding,
        } => execute_avg_pool_grad_cpu(
            plan,
            inputs[0],
            output,
            strides,
            window,
            start_padding,
            end_padding,
            *include_padding,
        )?,
        DmlOpKind::MaxPoolingGrad {
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
        } => execute_max_pool_grad_cpu(
            plan,
            inputs,
            output,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
        )?,
        DmlOpKind::ResampleGrad {
            mode,
            rounding,
            scales,
            input_offsets,
            output_offsets,
            ..
        } => execute_resample_grad_cpu(
            plan,
            inputs[0],
            output,
            *mode,
            *rounding,
            scales,
            input_offsets,
            output_offsets,
        )?,
        DmlOpKind::SliceGrad {
            offsets,
            sizes,
            strides,
        } => execute_slice_grad_cpu(plan, inputs[0], output, offsets, sizes, strides)?,
        DmlOpKind::ClipGrad { min, max, .. } => {
            execute_clip_grad_cpu(plan, inputs, output, *min, *max)?
        }
        DmlOpKind::LrnGrad {
            cross_channel,
            local_size,
            alpha,
            beta,
            bias,
        } => execute_lrn_grad_cpu(
            plan,
            inputs,
            output,
            *cross_channel,
            *local_size,
            *alpha,
            *beta,
            *bias,
        )?,
        DmlOpKind::BatchNormalizationGrad { epsilon } => {
            execute_batch_normalization_grad_cpu(plan, inputs, output, extras, *epsilon, false)?
        }
        DmlOpKind::BatchNormalizationTraining { epsilon } => {
            execute_batch_normalization_training_cpu(plan, inputs, output, extras, *epsilon)?
        }
        DmlOpKind::BatchNormalizationTrainingGrad { epsilon } => {
            execute_batch_normalization_grad_cpu(plan, inputs, output, extras, *epsilon, true)?
        }
        DmlOpKind::RoiAlignGrad {
            reduction,
            mode,
            spatial_scale_x,
            spatial_scale_y,
            input_pixel_offset,
            output_pixel_offset,
            minimum_samples_per_output,
            maximum_samples_per_output,
            align_regions_to_corners,
        } => execute_roi_align_grad_cpu(
            plan,
            inputs,
            output,
            *reduction,
            *mode,
            *spatial_scale_x,
            *spatial_scale_y,
            *input_pixel_offset,
            *output_pixel_offset,
            *minimum_samples_per_output,
            *maximum_samples_per_output,
            *align_regions_to_corners,
        )?,
        DmlOpKind::RandomGenerator { .. } => {
            execute_random_generator_cpu(plan, inputs[0], output, extras)?
        }
        DmlOpKind::NonZeroCoordinates => {
            execute_nonzero_cpu(plan, inputs[0], output, &mut *extras[0])?
        }
        DmlOpKind::DiagonalMatrix1 {
            offset_begin,
            offset_end,
            value,
        } => execute_diagonal1_cpu(
            plan,
            inputs.first().copied(),
            output,
            *offset_begin,
            *offset_end,
            *value,
        )?,
        DmlOpKind::MultiHeadAttention {
            scale,
            mask_filter_value,
            query_head_count,
            key_value_head_count,
            mask_type,
            has_bias,
            has_mask,
            ..
        } => execute_mha_cpu(
            plan,
            inputs,
            output,
            *scale,
            *mask_filter_value,
            *query_head_count,
            *key_value_head_count,
            *mask_type,
            *has_bias,
            *has_mask,
        )?,
    }
    if let Some(activation) = plan.fused_activation {
        for gid in 0..count {
            let index = output_index(&plan.output, gid);
            let value = load_scalar(output, index, dtype);
            store_scalar(output, index, dtype, activation_cpu(activation, value));
        }
    }
    Ok(())
}

pub(crate) fn output_index_of(desc: &DmlTensorDesc, gid: u64) -> u64 {
    let coords = coords_of(gid, &desc.sizes);
    index_of(&coords, &desc.strides)
}
