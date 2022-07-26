# IDA scripts

## Environmental preparation

- capstone
- networkx

## Basic function features

```python
1. Presematic_features_extract()
    {'bin_path':bin_path,
     'bfunc_data_dict':{func_name:bfunc_data}}
    bfunc_data: class BFunc()
    feature/
        1. CFG-13
            # num of basic blocks, edges, loops, SCCs, and back edges
            - cfg_size：基本块的数量
            - cfg_num_loops：自然循环结构数量
            - cfg_num_loops_inter：合并有交集的循环为一个循环之后的循环结构数量
            - cfg_num_scc：强连通分量数量：有向非强连通（双向边）图的极大强连通子图，称为强连通分量
            - cfg_num_backedges：循环边数
            # Avg./num of edges per a basic block
            - cfg_avg_degree：节点度的均值
            - cfg_num_degree：节点度的和
            # Avg./Sum of basic block, loop, and SCC sizes
            - cfg_avg_loopintersize：合并有交集的循环为一个循环之后的平均循环大小
            - cfg_avg_loopsize：自然循环结构的平均大小
            - cfg_avg_sccsize：强连通分量的平均大小
            - cfg_sum_loopintersize：合并有交集的循环为一个循环之后的循环大小之和
            - cfg_sum_loopsize：自然循环结构的大小之和
            - cfg_sum_sccsize：强连通分量的大小之和
        2. Instrs-28
            # num of all, arith, data transfer, cmp, and logic instrs.
            - inst_num_inst：指令数量总和
            - inst_num_arith：算术指令数量总和-ADD
            - inst_num_dtransfer：数据传输指令数量总和-MOV
            - inst_num_cmp：比较指令数量总和
            - inst_num_logic：逻辑指令数量总和-AND
            # num of shift, bit-manipulating, flfloat, misc instrs.
            - inst_num_shift：移位指令数量总和
            - inst_num_bitflag：位和字节指令数量总和
            - inst_num_floatinst：浮点指令数量总和
            - inst_num_misc：混杂指令数量总和
            # num of arith + shift, and data transfer + misc instrs.
            - inst_num_abs_arith：绝对算术指令数量和（arith & shift）
            - inst_num_abs_dtransfer：绝对数据传输指令数量和（dtransfer + misc）
            # num of all/unconditional/conditional control transfer instrs.
            - inst_num_ctransfer：控制转移指令数量总和-JMP
            - inst_num_cndctransfer：条件转移指令数量总和-JAE
            # Avg./num of all, arith, data transfer, cmp, and logic instrs. 
            - inst_avg_inst：指令平均数量
            - inst_avg_arith：算术指令平均数量
            - inst_avg_floatinst：浮点指令平均数量
            - inst_avg_dtransfer：数据传输指令平均数量
            - inst_avg_cmp：比较指令平均数量
            - inst_avg_logic：逻辑指令平均数量
            # Avg./num of shift, bit-manipulating, flfloat, misc instrs. 
            - inst_avg_shift：移位指令平均数量
            - inst_avg_bitflag：位和字节指令平均数量
            - inst_avg_misc：混杂指令平均数量-NOP
            # Avg./num of arith + shift, and data transfer + misc instrs. 
            - inst_avg_abs_arith：绝对算术指令平均数量
            - inst_avg_abs_dtransfer：绝对数据传输指令平均数量
            # Avg./num of all/unconditional/conditional control transfer instrs. 
            - inst_avg_abs_ctransfer：绝对控制转移指令平均数量（ctransfer + cond ctransfer）
            - inst_num_abs_ctransfer：绝对控制转移指令数量和
            - inst_avg_cndctransfer：条件转移指令平均数量
            - inst_avg_ctransfer：控制转移指令平均数量
        3. CG-6
            # num of callers, callees, imported callees
            - cg_num_callers：函数调用关系中调用函数名类别
            - cg_num_callees：函数调用关系中被调用函数名类别
            - cg_num_imported_callees：外部调用函数名类别
            # num of incoming/outgoing/imported calls
            - cg_num_incalls：调用入口数量=调用函数数量
            - cg_num_outcalls：调用出口数量=被调用函数数量
            - cg_num_imported_calls：外部调用数量
