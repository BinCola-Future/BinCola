
# BinCola

Official code of **BinCola: Self-supervised Contrastive Learning for Binary Code Similarity Detection**

![Illustrating the performance of the proposed jTrans](/figures/MRR-poolsize.png)
![Illustrating the performance of the proposed jTrans](/figures/TOP1-poolsize.png)
![Illustrating the performance of the proposed jTrans](/figures/TOP5-poolsize.png)

## Get Started

### Environmental preparation

- Python 3.8+
- PyTorch 1.10+
- CUDA 10.2+
- IDA pro 7.5+

[Dataset BINKIT](https://github.com/SoftSec-KAIST/binkit)

### Create virtual environment

```python
    conda create -n env_name python=3.8 # create
    Linux: source activate env_nam # activate
    Linux: source deactivate env_name
    conda info -e # check env
    conda remove -n env_name --all # delete
    # dependent libraries
    pip install torch torchvision torchaudio tensorboard numpy pandas coloredlogs matplotlib PyYAML seaborn sklearn tqdm info-nce-pytorch
```

## BCSA

1. 创建数据集

    ```python
        # create_input_list:生成要IDA分析的二进制列表
        # get_done_list:生成已完成IDA分析的二进制列表
        python preprocess_bcsa.py --data_folder "test_pkl/busybox_1.21" --out "input/"
    ```

2. IDA特征提取

    ```python
        # IDA分析在win下进行
        # python core/do_idascript.py --idapath "IDA_7.5" --idc "module/ida/fetch_funcdata_v7.5.py" --input_list "input/done_list_all_all_clang-4.0_gcc-4.9.4_all_all_all.txt" --log

        # 提取函数特征
        # python extract_features.py --input_list "input/done_list_all_all_clang-4.0_gcc-4.9.4_all_all_all.txt" --threshold 1

        # 贪心特征选择
        # 评价指标保存在log_out路径下的result_save文件夹
        # python test_roc.py --input_list "input/done_list_all_all_clang-4.0_gcc-4.9.4_all_all_all.txt" --config None
    ```

3. 模型训练

    ```python
        # 深度学习模型在linux下进行
        # 先将已完成IDA特征提取的.pickle文件上传到对应二进制文件夹
        # 选择不同的config文件进行不同测试
        # --config已硬编码
        # --train设置训练还是测试
        # 模型保存到log_out路径下的model_save文件夹
        # 评价指标保存在log_out路径下的result_save文件夹
        # save_funcdatalist_csv函数用于保存当前数据集下所有函数特征
        python train_dl.py --input_list "input/done_list_all_all_clang-4.0_gcc-4.9.4_all_all_all.txt" --use_tb --debug --train
    ```

4. 曲线绘制

    ```python
        python module/CodeAttention/DrawPic.py # 整合tiknib和attention在不同实验任务和不同指标上的曲线，对比作图
    ```

5. Top-K计算

    > 从测试集中取样test_funcs个正样本对，分成querys(带查询函数)和datas(被查询范围)，根据余弦相似度降序排序，目标值就是querys的索引值
    >
    > 1. 贪心算法querys取样test_funcs个
    > 2. 注意力网络querys取样test_funcs+valid_funcs个，和贪心算法个数相同

6. 实验效果
    1. [腾讯文档](https://docs.qq.com/sheet/DQ1NXTVhnZElSUUpR?u=63455d718f3547128d52a09f87337bde&tab=a4yvxh)
