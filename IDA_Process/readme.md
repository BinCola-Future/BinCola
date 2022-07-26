# IDA scripts

## environment
    ```python
        1. python_3.8
        2. IDAPro_7.5_SP
    ```

## configure run.py
    ```python
        1. log_folder: log file folder
        2. src_folder: bin file folder
        3. out_folder: pickle file folder
        4. ida_path: ida tool path
    ```

3. 运行

    ```python
        1. python run.py：启动IDA分析脚本，分析结果保存为同路径下.pickle文件
        2. Presematic_features_extract()：提取二进制函数预语义特征
            {'bfunc_data':bfunc_data_list,'bin_cg':bin_cg}
            bfunc_data_list的每一个变量是bclass.py中的BFunc类
            1. 提取函数特征-50
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
                4. Type-3
                    # num of parameter
                    - data_num_args：参数个数
                    # Mul of parameter type numbers
                    - data_mul_arg_type：参数类型编号乘积
                    # No. of return type
                    - data_ret_type：返回类型编号
        3. Acfg_extract()：提取二进制函数acfg特征
            1. 提取基本块特征-9
                raw_graphs.py:retrieveVec()
                1. consts_num：常量数
                2. strings_num：字符串个数
                3. offs：子节点个数
                4. numAs：算术指令数
                5. numCalls：调用指令数
                6. numIns：所有指令数
                7. numLIs：逻辑指令数
                8. numTIs：跳转指令数
                9. seqnum：指令分类及编号总数
            2. 提取函数特征-11
                acfg_extract/discovRe.py:get_discoverRe_feature()
                1. FunctionCalls：调用指令数
                2. LogicInstr：逻辑指令数
                3. Transfer：跳转指令数
                4. Locals：局部变量数（存在搜索范围过大的情况）
                5. BB：基本块个数
                6. Edges：CFG边数
                7. Incoming：被调用次数
                8. Instrs：所有指令数
                9. between：平均中介中心度（比较耗时）
                10. strings：所有字符串列表
                11. consts：所有常量列表
        4. done_save_db()函数：保存所有已分析二进制结果到数据库
        5. copy_done_file()函数：复制所有已分析二进制结果到单独的文件
    ```

4. 输出

    ```python
        1. 分析结果.pickle和.json保存在二进制同路径下
        2. log_folder目录：
            1. done_list.txt：保存所有已分析的二进制路径
            2. presematic_xxx.log：保存IDA-Presematic分析日志
            3. acfg_xxx.log：保存IDA-ACFG分析日志
            4. run_xxx.log：保存run.py运行日志
        
    ```
