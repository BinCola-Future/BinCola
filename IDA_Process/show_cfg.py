# coding-utf-8
# 基于angr提取函数cfg并可视化
import os
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib as mpl
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.stats import pearsonr
import pickle
import yaml
import random
from tqdm import tqdm
config = {
    "font.family": 'serif',
    "mathtext.fontset": 'stix',
    "font.serif": ['Times New Roman'],
}
plt.rcParams.update(config)

# 渐变颜色序列生成
def gen_colors(N):
    values = [int(i*250/N) for i in range(N)]
    colors=["#%02x%02x%02x"%(200,int(g),40)for g in values] # 250 250 250 ,g值越小越靠近0红色
    return colors

# circular_layout:将节点位置调整为圆形；
# random_layout:将节点随机的放在一个单位正方形内；
# shell_layout:将节点放于多个同心圆内；
# spring_layout:使用FR算法来定位节点；
# spectral_layout:利用图拉普拉斯的特征向量定位节点

def showCFG(bin_path,funcname,cfg,logdir):
    node_size = []
    node_color = []
    max_instnum = 0
    scaled = 10 # 缩放因子
    color_dict = {
        'red':'#DC143C',  # 大于20条指令
        'org':'#FF4500',  # 小于20
        'pur':'#BA55D3',  # 小于10
        'blue':'#00BFFF', # 小于5条指令

    }
    for node_id in cfg:
        num_inst = cfg.nodes[node_id]['bb_feature']['numIns']
        if num_inst > max_instnum:
            max_instnum = num_inst
    # 设置渐变色
    colors = gen_colors(max_instnum)

    for node_id in cfg:
        num_inst = cfg.nodes[node_id]['bb_feature']['numIns']
        node_size.append(800*(float(num_inst)/max_instnum)) # 基本块指令数
        if num_inst < 5:
            node_color.append(color_dict['blue'])
        elif num_inst < 10:
            node_color.append(color_dict['pur'])
        elif num_inst < 20:
            node_color.append(color_dict['org'])
        else:
            node_color.append(color_dict['red'])
        

    fig, ax = plt.subplots()
    nx.draw(
        cfg, 
        ax=ax,
        node_size=node_size,        # 节点大小
        node_color=node_color,      # 节点颜色
        pos=nx.shell_layout(cfg),   # 样式
        with_labels=True,           # 有无标签
        font_size=8,                # 标签大小
        width=0.5,                  # 边的宽度
        style='dashdot',              # 边的类型 solid | dashed虚线 | dotted | dashdot
    )
    
    # plt.show()
    fig.savefig(os.path.join(logdir,"{}@{}-cfg.pdf".format(os.path.basename(bin_path),funcname)),bbox_inches='tight')

# 把不同编译选项多个CFG绘制到一张图
def showCFGs(bin_name_list,funcname,cfg_list,out_folder):
    # fig, axes = plt.subplots(2,5,figsize=(40, 20),dpi=300)
    fig = plt.figure(dpi=300,figsize=(62,15))
    color_dict = {
            'red':'#DC143C',  # 大于20条指令
            'org':'#FF4500',  # 小于20
            'pur':'#BA55D3',  # 小于10
            'blue':'#00BFFF', # 小于5条指令
    }
    for idx,bin_name in enumerate(bin_name_list):
        node_size = []
        node_color = []
        max_instnum = 0
        scaled = 10 # 缩放因子
        cfg = cfg_list[idx]
        for node_id in cfg:
            num_inst = cfg.nodes[node_id]['bb_feature']['numIns']
            if num_inst > max_instnum:
                max_instnum = num_inst
        # 设置渐变色
        colors = gen_colors(max_instnum)

        for node_id in cfg:
            num_inst = cfg.nodes[node_id]['bb_feature']['numIns']
            node_size.append(1000*(float(num_inst)/max_instnum)) # 基本块指令数
            if num_inst < 5:
                node_color.append(color_dict['blue'])
            elif num_inst < 10:
                node_color.append(color_dict['pur'])
            elif num_inst < 20:
                node_color.append(color_dict['org'])
            else:
                node_color.append(color_dict['red'])
        plt.subplot(2, 8, idx+1)
        title = '_'.join(bin_name.split('_')[1:5])
        if 'obfus' in bin_name:
            title = title.split('clang-')[1]
        if 'gcc' in bin_name:
            title = title.replace('gcc', 'GCC')
        if 'clang' in bin_name:
            title = title.replace('clang', 'Clang')
        if 'arm' in bin_name:
                title = title.replace('arm', 'ARM')
        if 'mips' in bin_name:
            title = title.replace('mips', 'MIPS')
        plt.title(title,fontsize=40)
        nx.draw(
            cfg, 
            ax=plt.gca(),
            node_size=node_size,        # 节点大小
            node_color=node_color,      # 节点颜色
            pos=nx.shell_layout(cfg),   # 样式
            with_labels=True,           # 有无标签
            font_size=8,                # 标签大小
            width=1.0,                  # 边的宽度
            style='solid',              # 边的类型 solid | dashed虚线 | dotted | dashdot
        )
    x = [1.0]
    y = [1.0]
    s = 300
    plt.scatter(x, y, label="# of instr ≥ 20", c=color_dict['red'],s=s, alpha=1.0)
    plt.scatter(x, y, label="# of instr "+r'$\in$'+" [10,20)", c=color_dict['org'],s=s, alpha=1.0)
    plt.scatter(x, y, label="# of instr "+r'$\in$'+" [5,10)", c=color_dict['pur'],s=s, alpha=1.0)
    plt.scatter(x, y, label="# of instr < 5", c=color_dict['blue'],s=s, alpha=1.0)
    plt.legend(bbox_to_anchor=(-6.2,2.4,5.0,0.0), 
            loc="lower left",
            mode="expand", 
            borderaxespad=0, 
            ncol=4, 
            fontsize=60, 
            prop={'family':'Times New Roman','size':40}
    )
    plt.scatter(x, y, c='#FFFFFF',s=3*s+100, alpha=1.0)
    fig.savefig(os.path.join(out_folder,"{}@{}-cfg.pdf".format('all',funcname)),bbox_inches='tight')

# 把不同函数多个CFG绘制到一张图
def showMultiCFGs(config_check,func_name_list,cfg_list,out_folder):
    fig = plt.figure(dpi=300,figsize=(62,15))
    color_dict = {
            'red':'#DC143C',  # 大于20条指令
            'org':'#FF4500',  # 小于20
            'pur':'#BA55D3',  # 小于10
            'blue':'#00BFFF', # 小于5条指令
    }
    for idx,func_name in enumerate(func_name_list):
        node_size = []
        node_color = []
        max_instnum = 0
        scaled = 10 # 缩放因子
        cfg = cfg_list[idx]
        for node_id in cfg:
            num_inst = cfg.nodes[node_id]['bb_feature']['numIns']
            if num_inst > max_instnum:
                max_instnum = num_inst
        # 设置渐变色
        colors = gen_colors(max_instnum)

        for node_id in cfg:
            num_inst = cfg.nodes[node_id]['bb_feature']['numIns']
            node_size.append(1000*(float(num_inst)/max_instnum)) # 基本块指令数
            if num_inst < 5:
                node_color.append(color_dict['blue'])
            elif num_inst < 10:
                node_color.append(color_dict['pur'])
            elif num_inst < 20:
                node_color.append(color_dict['org'])
            else:
                node_color.append(color_dict['red'])
        plt.subplot(2, 8, idx+1)
        title = func_name
        plt.title(title,fontsize=40)
        nx.draw(
            cfg, 
            ax=plt.gca(),
            node_size=node_size,        # 节点大小
            node_color=node_color,      # 节点颜色
            pos=nx.shell_layout(cfg),   # 样式
            with_labels=True,           # 有无标签
            font_size=8,                # 标签大小
            width=1.0,                  # 边的宽度
            style='solid',              # 边的类型 solid | dashed虚线 | dotted | dashdot
        )
    x = [1.0]
    y = [1.0]
    s = 300
    plt.scatter(x, y, label="# of instr ≥ 20", c=color_dict['red'],s=s, alpha=1.0)
    plt.scatter(x, y, label="# of instr "+r'$\in$'+" [10,20)", c=color_dict['org'],s=s, alpha=1.0)
    plt.scatter(x, y, label="# of instr "+r'$\in$'+" [5,10)", c=color_dict['pur'],s=s, alpha=1.0)
    plt.scatter(x, y, label="# of instr < 5", c=color_dict['blue'],s=s, alpha=1.0)
    plt.legend(bbox_to_anchor=(-6.2,2.4,5.0,0.0), 
            loc="lower left",
            mode="expand", 
            borderaxespad=0, 
            ncol=4, 
            fontsize=60, 
            prop={'family':'Times New Roman','size':40}
    )
    plt.scatter(x, y, c='#FFFFFF',s=3*s+100, alpha=1.0)
    fig.savefig(os.path.join(out_folder,"{}@{}-cfg.pdf".format(config_check,'all')),bbox_inches='tight')

def GetCFG(pickle_file,funcname):
    cfg = None
    with open(pickle_file, "rb") as f:
        data = pickle.load(f)
        bfunc_data_dict = data['bfunc_data_dict']
        cfg = bfunc_data_dict[funcname].cfg
    return cfg

def GetFuncFea(pickle_file,funcname):
    with open(pickle_file, "rb") as f:
        data = pickle.load(f)
        bfunc_data_dict = data['bfunc_data_dict']
        basic_feature = bfunc_data_dict[funcname].info['feature']
        # bincola_feature = bfunc_data_dict[funcname].info['bincola_feature']
        # bincola_feature = bfunc_data_dict[funcname].info['arch_all_bincola_feature']
        bincola_feature = bfunc_data_dict[funcname].info['pos_select_arch_all_bincola_feature']
        jtrans_feature = bfunc_data_dict[funcname].info['jtrans_feature'].numpy()
        palm_featrue = bfunc_data_dict[funcname].info['palmtree_feature']

    return basic_feature,bincola_feature,jtrans_feature,palm_featrue

def GetBinColaFea(pickle_file,funcname):
    feature = None
    with open(pickle_file, "rb") as f:
        data = pickle.load(f)
        bfunc_data_dict = data['bfunc_data_dict']
        feature = bfunc_data_dict[funcname].info['bincola_feature']
    return feature

# 读取一定数量的函数特征
def GetFuncList(pickle_file,func_list,func_num):
    cfg_list = []
    func_basic_fea_list = []
    func_bincola_fea_list = []
    func_jtrans_fea_list = []
    func_palmtree_fea_list = []
    with open(pickle_file, "rb") as f:
        data = pickle.load(f)
        bfunc_data_dict = data['bfunc_data_dict']
        for func in func_list:
            func_basic_fea_list.append(bfunc_data_dict[func].info['feature'])
            # func_bincola_fea_list.append(bfunc_data_dict[func].info['bincola_feature'])
            # func_bincola_fea_list.append(bfunc_data_dict[func].info['arch_all_bincola_feature'])
            func_bincola_fea_list.append(bfunc_data_dict[func].info['pos_select_arch_all_bincola_feature'])
            func_jtrans_fea_list.append(bfunc_data_dict[func].info['jtrans_feature'].numpy())
            func_palmtree_fea_list.append(bfunc_data_dict[func].info['palmtree_feature'])
            cfg_list.append(bfunc_data_dict[func].cfg)
            del bfunc_data_dict[func]

        for func in random.sample(bfunc_data_dict.keys(),func_num):
            func_list.append(func)
            func_basic_fea_list.append(bfunc_data_dict[func].info['feature'])
            # func_bincola_fea_list.append(bfunc_data_dict[func].info['bincola_feature'])
            # func_bincola_fea_list.append(bfunc_data_dict[func].info['arch_all_bincola_feature'])
            func_bincola_fea_list.append(bfunc_data_dict[func].info['pos_select_arch_all_bincola_feature'])
            func_jtrans_fea_list.append(bfunc_data_dict[func].info['jtrans_feature'])
            func_palmtree_fea_list.append(bfunc_data_dict[func].info['palmtree_feature'])
            cfg_list.append(bfunc_data_dict[func].cfg)
    return func_list,cfg_list,func_basic_fea_list,func_bincola_fea_list,func_jtrans_fea_list,func_palmtree_fea_list

# data:2D
def heapMapPlot(data,key_list,title,logdir,sexi):
    '''
    基于相关性系数计算结果来绘制热力图
    '''
    colormap=plt.cm.RdBu
    data=np.array(data)
    # mask = np.zeros_like(data)
    # mask[np.triu_indices_from(mask)] = True

    fig,ax=plt.subplots(dpi=300,figsize=(25,25))
    sns.heatmap(pd.DataFrame(np.round(data,4),
    columns=key_list,index=key_list),
    annot=True,
    annot_kws={'family':'Times New Roman',"size":20},
    fmt='.2f',
    vmax=int(data.max()),
    vmin=int(data.min()),
    xticklabels=True,
    yticklabels=True,
    square=True,
    # mask=mask,
    cmap=sexi)  #"YlGnBu"
    # ax.set_xticklabels(key_list)
    # ax.set_yticklabels(key_list)
    # plt.title('Attention-Weight')
    plt.xticks(fontsize=20,fontproperties = 'Times New Roman')
    plt.yticks(fontsize=20,fontproperties = 'Times New Roman')
    cbar = ax.collections[0].colorbar
    cbar.ax.tick_params(labelsize=20)
    plt.savefig(os.path.join(logdir,title),bbox_inches='tight')

# 展示所有场景的基础特征相似度热力图，需要相似度矩阵
def showBasicFeaHeatmap(config_fname,funcname,bin_name_list,basic_fea_list,out_folder):
    with open(config_fname, "r") as f:
        config = yaml.load(f,Loader=yaml.FullLoader)
    features = sorted(config["features"])
    num_features = len(features)
    num_bins = len(bin_name_list)
    multi_feature = []
    matrix_fea = np.zeros((num_bins,num_bins),dtype=np.float64)
    for basic_fea in basic_fea_list:
        func_features = np.zeros(num_features, dtype=np.float64)
        for feature_idx, feature in enumerate(features):
            if feature not in basic_fea:
                continue
            val = basic_fea[feature]
            func_features[feature_idx] = val
        multi_feature.append(func_features)
    for i,fea_i in enumerate(multi_feature):
        for j,fea_j in enumerate(multi_feature):
            matrix_fea[i,j] = cosSim(fea_i,fea_j)
    
    new_bin_name_list = []
    for i,bin_name in enumerate(bin_name_list):
        new_bin_name_list.append('_'.join(bin_name.split('_')[1:5]))
        if 'obfus' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].split('clang-')[1]
        if 'gcc' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].replace('gcc', 'GCC')
        if 'clang' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].replace('clang', 'Clang')
        if 'arm' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].replace('arm', 'ARM')
        if 'mips' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].replace('mips', 'MIPS')
    # heapMapPlot(matrix_fea,new_bin_name_list,"basic_multi_comp_feature@{}.pdf".format(funcname),out_folder,'Blues')
    return matrix_fea,new_bin_name_list

# 展示所有场景的嵌入特征相似度热力图，需要相似度矩阵
def showEmbedFeaHeatmap(bin_name_list,funcname,method,embed_fea_list,out_folder):
    num_bins = len(bin_name_list)
    matrix_fea = np.zeros((num_bins,num_bins),dtype=np.float64)
    if method in ['jTrans','PalmTree']:
        for i,fea_i in enumerate(embed_fea_list):
            for j,fea_j in enumerate(embed_fea_list):
                if 'arm' in bin_name_list[i] or 'mips' in bin_name_list[i]:
                    matrix_fea[i,j] = 0.0
                elif 'arm' in bin_name_list[j] or 'mips' in bin_name_list[j]:
                    matrix_fea[i,j] = 0.0
                else:
                    matrix_fea[i,j] = pearsonrSim(fea_i,fea_j)
    else:
        for i,fea_i in enumerate(embed_fea_list):
            for j,fea_j in enumerate(embed_fea_list):
                matrix_fea[i,j] = pearsonrSim(fea_i,fea_j)
    
    new_bin_name_list = []
    for i,bin_name in enumerate(bin_name_list):
        new_bin_name_list.append('_'.join(bin_name.split('_')[1:5]))
        if 'obfus' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].split('clang-')[1]
        if 'gcc' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].replace('gcc', 'GCC')
        if 'clang' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].replace('clang', 'Clang')
        if 'arm' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].replace('arm', 'ARM')
        if 'mips' in bin_name:
            new_bin_name_list[i] = new_bin_name_list[i].replace('mips', 'MIPS')
    # heapMapPlot(matrix_fea,new_bin_name_list,"{}_multi_comp_feature@{}.pdf".format(method,funcname),out_folder,'Blues')
    return matrix_fea,new_bin_name_list



# 展示不同函数的基础特征相似度热力图，需要相似度矩阵
def showMultiBasicFeaHeatmap(config_check,config_fname,func_name_list,func_basic_fea_list,out_folder):
    with open(config_fname, "r") as f:
        config = yaml.load(f,Loader=yaml.FullLoader)
    features = sorted(config["features"])
    num_features = len(features)
    num_funcs = len(func_name_list)
    multi_feature = []
    matrix_fea = np.zeros((num_funcs,num_funcs),dtype=np.float64)
    for basic_fea in func_basic_fea_list:
        func_features = np.zeros(num_features, dtype=np.float64)
        for feature_idx, feature in enumerate(features):
            if feature not in basic_fea:
                continue
            val = basic_fea[feature]
            func_features[feature_idx] = val
        multi_feature.append(func_features)
    for i,fea_i in enumerate(multi_feature):
        for j,fea_j in enumerate(multi_feature):
            matrix_fea[i,j] = cosSim(fea_i,fea_j)
    # heapMapPlot(matrix_fea,func_name_list,"{}_basic_multi_func_feature.pdf".format(config_check),out_folder,'Blues')
    return matrix_fea,func_name_list

# 展示不同函数的基础特征相似度热力图，需要相似度矩阵
def showMultiEmbedFeaHeatmap(config_check,func_name_list,method,func_embed_fea_list,out_folder):
    num_funcs = len(func_name_list)
    matrix_fea = np.zeros((num_funcs,num_funcs),dtype=np.float64)
    for i,fea_i in enumerate(func_embed_fea_list):
        for j,fea_j in enumerate(func_embed_fea_list):
            matrix_fea[i,j] = cosSim(fea_i,fea_j)
    # heapMapPlot(matrix_fea,func_name_list,"{}_{}_multi_func_feature.pdf".format(config_check,method),out_folder,'Blues')
    return matrix_fea,func_name_list


def cosSim(x,y):
    '''
    余弦相似度，值越大，越相似 [-1,1]
    '''
    tmp=np.sum(x*y)
    non=np.linalg.norm(x)*np.linalg.norm(y)
    return np.round(tmp/float(non),9)

def pearsonrSim(x,y):
    '''
    皮尔森线性相关系数，值越大，越相关 [-1,1]
    '''
    return np.round(pearsonr(x,y)[0],9)

# 查找所有pickle中共有的函数
def GetExistFunc(all_file_list):
    all_func = []
    exist_func = []
    for file in tqdm(all_file_list):
        with open(file, "rb") as f:
            data = pickle.load(f)
            bfunc_data_dict = data['bfunc_data_dict']
            func_list = bfunc_data_dict.keys()
        all_func.append(func_list)
    for func in tqdm(all_func[0]):
        if '.' not in func and all(func in temp for temp in all_func[1:]):
            exist_func.append(func)
    return exist_func


# 获取所有文件名，包括子文件夹
def check_file(file_path):
    os.chdir(file_path)
    all_file = os.listdir()
    files = []
    for f in all_file:
        files.append(file_path+'/'+f)
    return files

def Merge_Heatmap(config_name,config_check_name,funcname,bin_name_list,basic_feature_list,bincola_feature_list,jtrans_feature_list,palm_feature_list,func_list,func_basic_fea_list,func_bincola_fea_list,func_jtrans_fea_list,func_palmtree_fea_list,out_folder):
    matrix_fea_list = []
    key_name_list = []
    title_list = []
    matrix_fea,key_name = showBasicFeaHeatmap(config_name,funcname,bin_name_list,basic_feature_list,out_folder)
    matrix_fea_list.append(matrix_fea)
    key_name_list.append(key_name)
    title_list.append('basic_various_scenarios')

    matrix_fea,key_name = showEmbedFeaHeatmap(bin_name_list,funcname,'BinCola',bincola_feature_list,out_folder)
    matrix_fea_list.append(matrix_fea)
    key_name_list.append(key_name)
    title_list.append('BinCola_various_scenarios')
    
    matrix_fea,key_name = showEmbedFeaHeatmap(bin_name_list,funcname,'jTrans',jtrans_feature_list,out_folder)
    matrix_fea_list.append(matrix_fea)
    key_name_list.append(key_name)
    title_list.append('jTrans_various_scenarios')

    matrix_fea,key_name = showEmbedFeaHeatmap(bin_name_list,funcname,'PalmTree',palm_feature_list,out_folder)
    matrix_fea_list.append(matrix_fea)
    key_name_list.append(key_name)
    title_list.append('PalmTree_various_scenarios')

    matrix_fea,key_name = showMultiBasicFeaHeatmap(config_check_name,config_name,func_list,func_basic_fea_list,out_folder)
    matrix_fea_list.append(matrix_fea)
    key_name_list.append(key_name)
    title_list.append('basic_various_functions')
    
    matrix_fea,key_name = showMultiEmbedFeaHeatmap(config_check_name,func_list,'bincola',func_bincola_fea_list,out_folder)
    matrix_fea_list.append(matrix_fea)
    key_name_list.append(key_name)
    title_list.append('BinCola_various_functions')
    
    matrix_fea,key_name = showMultiEmbedFeaHeatmap(config_check_name,func_list,'jTrans',func_jtrans_fea_list,out_folder)
    matrix_fea_list.append(matrix_fea)
    key_name_list.append(key_name)
    title_list.append('jTrans_various_functions')
    
    matrix_fea,key_name = showMultiEmbedFeaHeatmap(config_check_name,func_list,'PalmTree',func_palmtree_fea_list,out_folder)
    matrix_fea_list.append(matrix_fea)
    key_name_list.append(key_name)
    title_list.append('PalmTree_various_functions')

    Draw_merge_heatmap(matrix_fea_list,key_name_list,title_list,funcname,out_folder)

def Draw_merge_heatmap(matrix_fea_list,key_name_list,title_list,funcname,out_folder):
    colormap=plt.cm.RdBu
    # mask = np.zeros_like(data)
    # mask[np.triu_indices_from(mask)] = True
    fig = plt.figure(dpi=300,figsize=(45,20))
    cmap_style = 'Blues'
    for idx,matrix_fea in tqdm(enumerate(matrix_fea_list)):
        data=np.array(matrix_fea)
        key_list = key_name_list[idx]
        plt.subplot(2, 4, idx+1)
        ax = plt.gca()
        if idx%4 == 0:
            sns.heatmap(pd.DataFrame(np.round(data,4),
                columns=key_list,index=key_list),
                annot=True,
                annot_kws={'family':'Times New Roman',"size":10},
                fmt='.2f',
                vmax=int(data.max()),
                vmin=int(data.min()),
                xticklabels=False,
                yticklabels=True,
                square=True,
                # linewidths=.05,
                # mask=mask,
                cmap=cmap_style
            )  #"YlGnBu"
        else:
            sns.heatmap(pd.DataFrame(np.round(data,4),
                columns=key_list,index=key_list),
                annot=True,
                annot_kws={'family':'Times New Roman',"size":10},
                fmt='.2f',
                vmax=int(data.max()),
                vmin=int(data.min()),
                xticklabels=False,
                yticklabels=False,
                square=True,
                # linewidths=.05,
                # mask=mask,
                cmap=cmap_style
            )  #"YlGnBu"
        # ax.set_xticklabels(key_list)
        # ax.set_yticklabels(key_list)
        plt.title(title_list[idx],fontsize=30,y=1.05)
        plt.xticks(fontsize=20,fontproperties = 'Times New Roman')
        plt.yticks(fontsize=20,fontproperties = 'Times New Roman')
        cbar = ax.collections[0].colorbar
        cbar.ax.tick_params(labelsize=20)

    fig.savefig(os.path.join(out_folder,"{}_PosSelect_Normal_All_Merge_Heatmap_{}.pdf".format(cmap_style,funcname)),bbox_inches='tight')



if __name__ == "__main__":
    src_folder = r'D:\program_jiang\Pro\BCSA\Analysis_Scripts\IDA_Process\example\showcfg_pickle'
    out_folder = r'D:\program_jiang\Pro\BCSA\Analysis_Scripts\IDA_Process\example\showheatmap_out'
    funcname = 'ppd_create_buffer'
    os.makedirs(out_folder,exist_ok=True)
    all_file_list = check_file(src_folder)
    config_name = r'D:\program_jiang\Pro\BCSA\Analysis_Scripts\IDA_Process\example\config\config_gnu_normal_all_type.yml'
    config_name_order = [
        'gcc-4.9.4_x86_64_O0',
        'gcc-4.9.4_x86_64_O1',
        'gcc-4.9.4_x86_64_O2',
        'gcc-4.9.4_x86_64_O3',
        'clang-4.0_x86_64_O0',
        'clang-4.0_x86_64_O1',
        'clang-4.0_x86_64_O2',
        'clang-4.0_x86_64_O3',
        'gcc-4.9.4_arm_64_O2',
        'gcc-4.9.4_mips_64_O2',
        'clang-4.0_arm_64_O2',
        'clang-4.0_mips_64_O2',
        'clang-obfus-bcf_x86_64_O2',
        'clang-obfus-fla_x86_64_O2',
        'clang-obfus-sub_x86_64_O2',
        'clang-obfus-all_x86_64_O2'
    ]
    # 判断不同编译选项之间的相似度
    # exist_func = GetExistFunc(all_file_list)
    func_list = [
        'dir_name',
        # 'ds_cat_sprintf',
        # 'ds_unsafe_cat_sprintf',
        # 'pair_hash_1',
        # 'pair_hash_2',
        # 'da_free_content',
        # 'a2ps_handle_string_options',
        # 'base_name',
        # 'hash_free_items',
        # 'ppdrestart',
        # 'ppd_create_buffer',
    ]
    for funcname in tqdm(func_list):
        bin_name_list = []
        cfg_list = []
        basic_feature_list = []
        bincola_feature_list = []
        jtrans_feature_list = []
        palm_feature_list = []
        for config in tqdm(config_name_order):
            for file in all_file_list:
                if config in file:
                    basic_feature,bincola_feature,jtrans_feature,palm_featrue = GetFuncFea(file,funcname)
                    bin_name_list.append(os.path.basename(file))
                    basic_feature_list.append(basic_feature)
                    bincola_feature_list.append(bincola_feature)
                    jtrans_feature_list.append(jtrans_feature)
                    palm_feature_list.append(palm_featrue)
                    # cfg = GetCFG(file,funcname)
                    # cfg_list.append(cfg)
                    break
        # showCFGs(bin_name_list,funcname,cfg_list,out_folder)
        # showBasicFeaHeatmap(config_name,funcname,bin_name_list,basic_feature_list,out_folder)
        # showEmbedFeaHeatmap(bin_name_list,funcname,'BinCola',bincola_feature_list,out_folder)
        # showEmbedFeaHeatmap(bin_name_list,funcname,'jTrans',jtrans_feature_list,out_folder)
        # showEmbedFeaHeatmap(bin_name_list,funcname,'PalmTree',palm_feature_list,out_folder)

    # 判断不同函数之间的相似度
    config_check_name = 'gcc-4.9.4_x86_64_O2'
    func_num = 0
    func_list = [
        'dir_name',
        'ds_cat_sprintf',
        'ds_unsafe_cat_sprintf',
        'pair_hash_1',
        'pair_hash_2',
        'da_free_content',
        'a2ps_handle_string_options',
        'base_name',
        'hash_free_items',
        'ppdrestart',
        'wx_self_print',
        'ps_print_string',
        'style_sheet_mixed_new',
        'ds_print_stats',
        'pair_table_load',
        'yy_get_previous_state_1',
    ]
    for file in all_file_list:
        if config_check_name in file:
            func_list,cfg_list,func_basic_fea_list,func_bincola_fea_list,func_jtrans_fea_list,func_palmtree_fea_list = GetFuncList(file,func_list,func_num)
    #         # showMultiBasicFeaHeatmap(config_check_name,config_name,func_list,func_basic_fea_list,out_folder)
    #         # showMultiEmbedFeaHeatmap(config_check_name,func_list,'bincola',func_bincola_fea_list,out_folder)
    #         showMultiEmbedFeaHeatmap(config_check_name,func_list,'jTrans',func_jtrans_fea_list,out_folder)
    #         showMultiEmbedFeaHeatmap(config_check_name,func_list,'PalmTree',func_palmtree_fea_list,out_folder)
    #         # showMultiCFGs(config_check_name,func_list,cfg_list,out_folder)

    # 汇总单个函数多场景以及多个函数热力图
    Merge_Heatmap(
        config_name,
        config_check_name,
        func_list[0],
        bin_name_list,
        basic_feature_list,
        bincola_feature_list,
        jtrans_feature_list,
        palm_feature_list,
        func_list,
        func_basic_fea_list,
        func_bincola_fea_list,
        func_jtrans_fea_list,
        func_palmtree_fea_list,
        out_folder
    )

