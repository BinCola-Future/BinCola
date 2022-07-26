
# BinCola

Official code of **BinCola: Self-supervised Contrastive Learning for Binary Code Similarity Detection**

![Illustrating the performance of the proposed jTrans](/figures/TOP1-poolsize.png)

## Get Started

### Environmental preparation

- Python 3.8+
- PyTorch 1.10+
- CUDA 10.2+
- IDA pro 7.5+

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

### Datasets

[Dataset BINKIT](https://github.com/SoftSec-KAIST/binkit)

### Quick Start

**a. Get code of BinCola.**

```python
git clone https://github.com/BinCola-Future/BinCola.git && cd BinCola
```

Download [experiments.tar.gz](https://cloud.vul337.team:8443/s/wmqzYFyJnSEfEgm) and extract them.

```python
tar -xzvf experiments.tar.gz
```

**b. Preprocess binary files**

```python
python IDA_Process/run.py
```

**c. Train and evaluate the model**

```python
# Generate a list of training files
python core/preprocess_bcsa.py
# Train and evaluate the model
python core/train.py --debug --train --input_list "training file list path"
```
