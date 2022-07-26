# coding:utf-8
import matplotlib.pyplot as plt
import matplotlib.image as img
from matplotlib.pyplot import MultipleLocator
# 从pyplot导入MultipleLocator类，这个类用于设置刻度间隔
import matplotlib
import json
# print(matplotlib.matplotlib_fname())
# print(matplotlib.get_cachedir())
config = {
    "font.family": 'serif',
    "mathtext.fontset": 'stix',
    "font.serif": ['Times New Roman'],
}
plt.rcParams.update(config)

from sklearn import metrics
import numpy as np
import pandas as pd
from tqdm import tqdm
import os
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics.pairwise import cosine_similarity
from shutil import copyfile
from scipy.interpolate import make_interp_spline
import seaborn as sns
import heapq
import math

# 绘制poolsize直线图
def Draw_Poolsize_Topk_Polyline(csv_files,curve_label,font_size,logdir):
    os.makedirs(logdir, exist_ok=True)
    show_dict = {}
    for i in range(len(csv_files)):
        csv = csv_files[i]
        dataframe = pd.read_csv(csv)
        show_dict[curve_label[i]] = {}
        poolsize = np.array(dataframe['poolsize'])[0:101]
        options = dataframe['options']
        options_set = list(set(options))
        options_set.sort()
        TOP1 = dataframe['TOP1']
        TOP5 = dataframe['TOP5']
        MRR =  dataframe['MRR']
        for j in range(len(options)):
            if options[j] not in show_dict[curve_label[i]]:
                show_dict[curve_label[i]][options[j]] = {
                    'TOP1':[TOP1[j]],
                    'TOP5':[TOP5[j]],
                    'MRR':[MRR[j]]
                }
            else:
                show_dict[curve_label[i]][options[j]]['TOP1'].append(TOP1[j])
                show_dict[curve_label[i]][options[j]]['TOP5'].append(TOP5[j])
                show_dict[curve_label[i]][options[j]]['MRR'].append(MRR[j])
            
    poolsize_log10 = np.array(list(map(lambda x : math.log10(x),poolsize)))
    
    for para in ['TOP1','TOP5','MRR']:
        Draw_Polyline(show_dict,poolsize,options_set,para,font_size)
        print('Draw_Polyline_{}_Poolsize'.format(para))
        
    
def Draw_Polyline(show_dict,poolsize,options_set,para,font_size):
    CB91_Blue = '#2CBDFE'
    CB91_Green = '#47DBCD'
    CB91_Pink = '#F3A0F2'
    CB91_Purple = '#9D2EC5'
    CB91_Violet = '#661D98'
    CB91_Amber = '#F5B14C'
    colors = [CB91_Blue, CB91_Amber, CB91_Pink, CB91_Green, CB91_Purple, CB91_Violet]
    linestyles = ['-','--','-.',':']
    markers = ['o','s','v','*']
    if para == 'TOP1':
        y_label = '$\it{Recall@1}$'
    elif para == 'TOP5':
        y_label = '$\it{Recall@5}$'
    elif para == 'MRR':
        y_label = '$\it{MRR}$'
    # plt.style.use('seaborn-whitegrid')
    y = [0.0,0.2,0.4,0.6,0.8,1.0]
    plt.style.use('bmh')
    fig = plt.figure(dpi=300,figsize=(65,25))
    for id,option in enumerate(options_set):
        plt.subplot(2, 5, id+1)
        plt.title(option,fontsize=font_size)
        plt.xticks(fontsize=font_size)
        plt.yticks(y,fontsize=font_size)
        # plt.xlabel(r'log$_\mathrm{10}$(Poolsize)',fontsize=font_size)
        plt.xlabel('$\it{Poolsize}$',fontsize=font_size)
        plt.ylabel(y_label,fontsize=font_size)
        x_major_locator=MultipleLocator(200)
        # 把x轴的刻度间隔设置为1，并存在变量里
        y_major_locator=MultipleLocator(0.2)
        # 把y轴的刻度间隔设置为10，并存在变量里
        ax=plt.gca()
        # ax为两条坐标轴的实例
        ax.xaxis.set_major_locator(x_major_locator)
        # 把x轴的主刻度设置为1的倍数
        ax.yaxis.set_major_locator(y_major_locator)
        # 把y轴的主刻度设置为10的倍数
        plt.xlim(-50,1000)
        # 把x轴的刻度范围设置为-0.5到11，因为0.5不满一个刻度间隔，所以数字不会显示出来，但是能看到一点空白
        plt.ylim(-0.05,1.05)
        # 把y轴的刻度范围设置为-5到110，同理，-5不会标出来，但是能看到一点空白
        for i,method in enumerate(show_dict.keys()):
            top1 = np.array(show_dict[method][option][para])
            # plt.plot(poolsize_log10, top1, label=method, color=colors[i], marker=markers[i], linestyle=linestyles[i])
            plt.plot(poolsize, top1, label=method, color=colors[i], linestyle=linestyles[i])
    plt.legend(bbox_to_anchor=(-2.9,2.3,2,0.2), loc="lower left",mode="expand", borderaxespad=0, ncol=3, fontsize=font_size, 
               prop={'family':'Times New Roman','size':font_size+5})
    # fig.tight_layout()
    fig.savefig(str(logdir) + "/{}-poolsize.pdf".format(para),bbox_inches='tight')
    plt.close(fig)
    

# 绘制vulner_patch折线图
def Draw_Vul_Patch_Sim_Polyline(json_files,curve_label,font_size,logdir):
    cve_name = 'CVE-2013-6450'
    func_name = 'dtls1_hm_fragment_free'
    os.makedirs(logdir, exist_ok=True)
    show_dict = {}
    for i in range(len(json_files)):
        file_path = json_files[i]
        with open(file_path,'r') as f:
            data_list = json.loads(f.read())
            vulner_sim = []
            patch_sim = []
            for res in data_list:
                if res[0] == cve_name and res[1] == func_name:
                    for j in range(4,len(res)):
                        sim = res[j].split(' ')[1]
                        vulner_sim.append(float(sim.split('/')[0]))
                        patch_sim.append(float(sim.split('/')[1]))
        show_dict[curve_label[i]] = {
            'vulner_sim':vulner_sim,
            'patch_sim':patch_sim
        }
    
    for para in ['vulner_sim','patch_sim']:
        Draw_Each_Polyline(show_dict,para,font_size)
        print('Draw_Polyline_{}_Poolsize'.format(para))

def Draw_Each_Polyline(show_dict,para,font_size):
    CB91_Blue = '#2CBDFE'
    CB91_Green = '#47DBCD'
    CB91_Pink = '#F3A0F2'
    CB91_Purple = '#9D2EC5'
    CB91_Violet = '#661D98'
    CB91_Amber = '#F5B14C'
    colors = [CB91_Blue, CB91_Amber, CB91_Pink, CB91_Green, CB91_Purple, CB91_Violet]
    linestyles = ['-','--','-.',':']
    markers = ['o','s','v','*']
    if para == 'vulner_sim':
        y_label = 'Similarity to Vulnerable Version (e)'
    elif para == 'patch_sim':
        y_label = 'Similarity to Patched Version (f)'
    # plt.style.use('seaborn-whitegrid')
    versions = ['0',
                'a',
                'b',
                'c',
                'd',
                'e',
                'f',
                'g',
                'h',
                'i',
                'j',
                'k',
                'l',
                'm',
                'n',
                'o',
                'p',
                'q',
                'r',
                's',
                't',
                'u']
    y = [0.0,0.2,0.4,0.6,0.8,1.0]
    x = range(0, len(versions))
    plt.style.use('bmh')
    fig = plt.figure(dpi=300,figsize=(15,5))
    plt.xticks(ticks=x, labels=versions, fontsize=font_size)
    plt.yticks(y,fontsize=font_size)
    # plt.xlabel(r'log$_\mathrm{10}$(Poolsize)',fontsize=font_size)
    # plt.xlabel('Version',fontsize=font_size)
    plt.ylabel(y_label,fontsize=font_size)
    for i,method in enumerate(show_dict.keys()):
        sim_value = np.array(show_dict[method][para])
        # plt.plot(poolsize_log10, top1, label=method, color=colors[i], marker=markers[i], linestyle=linestyles[i])
        plt.plot(x, sim_value, label=method, color=colors[i], linestyle=linestyles[i])
    # plt.legend(bbox_to_anchor=(0.0,1.0,1.5,0.0), loc="lower left",mode="expand", borderaxespad=0, ncol=4, fontsize=font_size, 
    #            prop={'family':'Times New Roman','size':font_size+5})
    loc = 'lower right'
    if para == 'vulner_sim':
        loc = 'lower left'
    plt.legend(loc=loc, fontsize=font_size)
    # fig.tight_layout()
    fig.savefig(str(logdir) + "/{}.pdf".format(para),bbox_inches='tight')
    plt.close(fig)

# 根据tsv文件绘制曲线
def Draw_By_tsv(tsv_files,curve_label,curve_name,font_size,logdir):
    os.makedirs(logdir, exist_ok=True)
    colors = ['r','b']
    linestyles = ['-','--']
    if curve_name == 'best_test_roc':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size)
        plt.yticks(fontsize=font_size)
        plt.xlabel('False positive rate',fontsize=font_size)
        plt.ylabel('True positive rate',fontsize=font_size)
        
        for i in range(len(tsv_files)):
            tsv = tsv_files[i]
            thresholds = []
            tprs = []
            fprs = []
            with open(tsv, "r") as the_file:
                content = the_file.readlines()
                for line in content[1:]:
                    line.strip()
                    threshold = float(line.split('\t')[0])
                    tpr = float(line.split('\t')[1])
                    fpr = float(line.split('\t')[2])
                    thresholds.append(threshold)
                    tprs.append(tpr)
                    fprs.append(fpr)
            plt.plot(fprs, tprs, color=colors[i], linestyle=linestyles[i], label=curve_label[i])
        plt.legend(loc='lower right',fontsize=20)
        plt.tight_layout()
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)


    elif curve_name == 'F1score-CDF':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size)
        plt.yticks(fontsize=font_size)
        plt.xlabel('F1_score',fontsize=font_size)
        plt.ylabel('percentage',fontsize=font_size)
        for i in range(len(tsv_files)):
            tsv = tsv_files[i]
            F1_scores = []
            percentages = []
            with open(tsv, "r") as the_file:
                content = the_file.readlines()
                for line in content[1:]:
                    line.strip()
                    F1_score = float(line.split('\t')[0])
                    percentage = float(line.split('\t')[1])
                    F1_scores.append(F1_score)
                    percentages.append(percentage)
            plt.plot(F1_scores, percentages, color=colors[i], linestyle=linestyles[i], label=curve_label[i])
        plt.legend(loc='best',fontsize=20)
        plt.tight_layout()
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)

    elif curve_name == 'pre_recall':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size)
        plt.yticks(fontsize=font_size)
        plt.xlabel('recall',fontsize=font_size)
        plt.ylabel('precision',fontsize=font_size)
        for i in range(len(tsv_files)):
            tsv = tsv_files[i]
            precisions = []
            recalls = []
            with open(tsv, "r") as the_file:
                content = the_file.readlines()
                for line in content[1:]:
                    line.strip()
                    threshold = float(line.split('\t')[0])
                    precision = float(line.split('\t')[1])
                    recall = float(line.split('\t')[2])
                    precisions.append(precision)
                    recalls.append(recall)
            plt.plot(recalls, precisions, color=colors[i], linestyle=linestyles[i], label=curve_label[i])
        plt.legend(loc='lower left',fontsize=20)
        plt.tight_layout()
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)

    elif curve_name == 'thresholds_f1_score':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size)
        plt.yticks(fontsize=font_size)
        plt.xlabel('thresholds',fontsize=font_size)
        plt.ylabel('f1_score',fontsize=font_size)
        for i in range(len(tsv_files)):
            tsv = tsv_files[i]
            thresholds = []
            f1_scores = []
            with open(tsv, "r") as the_file:
                content = the_file.readlines()
                for line in content[1:]:
                    line.strip()
                    threshold = float(line.split('\t')[0])
                    f1_score = float(line.split('\t')[1])
                    thresholds.append(threshold)
                    f1_scores.append(f1_score)
            plt.plot(thresholds, f1_scores, color=colors[i], linestyle=linestyles[i], label=curve_label[i])
        plt.legend(loc='lower left',fontsize=20)
        plt.tight_layout()
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)

# 根据csv文件绘制曲线，直接读取对应列
def Draw_By_csv(csv_files,curve_label,curve_name,font_size,logdir):
    os.makedirs(logdir, exist_ok=True)
    colors = ['r','b']
    linestyles = ['-','--']
    
    if curve_name == 'best_test_roc':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size)
        plt.yticks(fontsize=font_size)
        plt.xlabel('False positive rate',fontsize=font_size)
        plt.ylabel('True positive rate',fontsize=font_size)
        for i in range(len(csv_files)):
            csv = csv_files[i]
            dataframe = pd.read_csv(csv)
            tprs = dataframe['tprs']
            fprs = dataframe['fprs']
            plt.plot(fprs, tprs, color=colors[i], linestyle=linestyles[i], label=curve_label[i])
        plt.legend(loc='lower right',fontsize=20)
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)


    elif curve_name == 'F1score-CDF':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size)
        plt.yticks(fontsize=font_size)
        plt.xlabel('F1_score',fontsize=font_size)
        plt.ylabel('percentage',fontsize=font_size)
        for i in range(len(csv_files)):
            csv = csv_files[i]
            dataframe = pd.read_csv(csv)
            F1_scores = dataframe['CDF_X']
            percentages = dataframe['f1_scores_percents']
            plt.plot(F1_scores, percentages, color=colors[i], linestyle=linestyles[i], label=curve_label[i])
        plt.legend(loc='best',fontsize=20)
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)

    elif curve_name == 'pre_recall':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size)
        plt.yticks(fontsize=font_size)
        plt.xlabel('recall',fontsize=font_size)
        plt.ylabel('precision',fontsize=font_size)
        for i in range(len(csv_files)):
            csv = csv_files[i]
            dataframe = pd.read_csv(csv)
            precisions = dataframe['precision']
            recalls = dataframe['recall']
            plt.plot(recalls, precisions, color=colors[i], linestyle=linestyles[i], label=curve_label[i])
        plt.legend(loc='lower left',fontsize=20)
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)
    
    elif curve_name == 'thresholds_f1_score':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size)
        plt.yticks(fontsize=font_size)
        plt.xlabel('thresholds',fontsize=font_size)
        plt.ylabel('f1_score',fontsize=font_size)
        for i in range(len(csv_files)):
            csv = csv_files[i]
            dataframe = pd.read_csv(csv)
            thresholds = dataframe['threshold']
            f1_scores = dataframe['f1_scores']
            plt.plot(thresholds, f1_scores, color=colors[i], linestyle=linestyles[i], label=curve_label[i])
        plt.legend(loc='lower left',fontsize=20)
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)

def smooth_curve(points, factor=0.8):   
    smoothed_points = []   
    for point in points:     
        if smoothed_points:       
            previous = smoothed_points[-1]   
            # 上一个节点*0.8+当前节点*0.2
            smoothed_points.append(previous * factor + point * (1 - factor))     
        else:  
            # 添加point
            smoothed_points.append(point)   
    return smoothed_points
# 支持tsv csv两种文件
def Draw_By_xsv(xsv_files,curve_label,curve_name,font_size,logdir):
    os.makedirs(logdir, exist_ok=True)
    CB91_Blue = '#2CBDFE'
    CB91_Green = '#47DBCD'
    CB91_Pink = '#F3A0F2'
    CB91_Purple = '#9D2EC5'
    CB91_Violet = '#661D98'
    CB91_Amber = '#F5B14C'
    colors = [CB91_Blue, CB91_Amber, CB91_Pink, CB91_Green, CB91_Purple, CB91_Violet]
    # colors = ['r','b']
    linestyles = ['-','--','-.',':']
    
    # plt.style.use('seaborn-whitegrid')
    plt.style.use('bmh')
    if curve_name == 'best_test_roc':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size-5)
        plt.yticks(fontsize=font_size-5)
        plt.xlabel('False positive rate',fontsize=font_size)
        plt.ylabel('True positive rate',fontsize=font_size)
        plt.xlim(0.0,0.5)
        for i in range(len(xsv_files)):
            xsv = xsv_files[i]
            thresholds = []
            tprs = []
            fprs = []
            if xsv.split('.')[-1] == 'tsv':
                with open(xsv, "r") as the_file:
                    content = the_file.readlines()
                    for line in content[1:]:
                        line.strip()
                        threshold = float(line.split('\t')[0])
                        tpr = float(line.split('\t')[1])
                        fpr = float(line.split('\t')[2])
                        thresholds.append(threshold)
                        tprs.append(tpr)
                        fprs.append(fpr)
            elif xsv.split('.')[-1] == 'csv':
                dataframe = pd.read_csv(xsv)
                tprs = dataframe['tprs']
                fprs = dataframe['fprs']
            plt.plot(fprs, tprs, color=colors[i], linestyle=linestyles[i % 4], label=curve_label[i])
        plt.legend(loc='lower right',fontsize=font_size-10)
        plt.tight_layout()
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf",bbox_inches='tight')
        plt.close(fig)


    elif curve_name == 'F1score-CDF':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size-5)
        plt.yticks(fontsize=font_size-5)
        plt.xlabel('F1_score',fontsize=font_size)
        plt.ylabel('percentage',fontsize=font_size)
        for i in range(len(xsv_files)):
            xsv = xsv_files[i]
            F1_scores = []
            percentages = []
            if xsv.split('.')[-1] == 'tsv':
                with open(xsv, "r") as the_file:
                    content = the_file.readlines()
                    for line in content[1:]:
                        line.strip()
                        F1_score = float(line.split('\t')[0])
                        percentage = float(line.split('\t')[1])
                        F1_scores.append(F1_score)
                        percentages.append(percentage)
            elif xsv.split('.')[-1] == 'csv':
                dataframe = pd.read_csv(xsv)
                F1_scores = dataframe['CDF_X']
                percentages = dataframe['f1_scores_percents']
            plt.plot(F1_scores, percentages, color=colors[i], linestyle=linestyles[i % 4], label=curve_label[i])
        plt.legend(loc='best',fontsize=font_size-10)
        plt.tight_layout()
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)

    elif curve_name == 'pre_recall':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size-5)
        plt.yticks(fontsize=font_size-5)
        plt.xlabel('recall',fontsize=font_size)
        plt.ylabel('precision',fontsize=font_size)
        plt.xlim(0.6,1.0)
        x = MultipleLocator(0.1)    # x轴每10一个刻度
        # 设置刻度间隔
        ax = plt.gca()
        ax.xaxis.set_major_locator(x)
        for i in range(len(xsv_files)):
            xsv = xsv_files[i]
            precisions = []
            recalls = []
            if xsv.split('.')[-1] == 'tsv':
                with open(xsv, "r") as the_file:
                    content = the_file.readlines()
                    for line in content[1:]:
                        line.strip()
                        threshold = float(line.split('\t')[0])
                        precision = float(line.split('\t')[1])
                        recall = float(line.split('\t')[2])
                        precisions.append(precision)
                        recalls.append(recall)
            elif xsv.split('.')[-1] == 'csv':
                dataframe = pd.read_csv(xsv)
                precisions = dataframe['precision']
                recalls = dataframe['recall']
            plt.plot(recalls, precisions, color=colors[i], linestyle=linestyles[i % 4], label=curve_label[i])
        plt.legend(loc='lower left',fontsize=font_size-10)
        plt.tight_layout()
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)

    elif curve_name == 'thresholds_f1_score':
        fig = plt.figure()
        # plt.title(curve_name)
        plt.xticks(fontsize=font_size-5)
        plt.yticks(fontsize=font_size-5)
        plt.xlabel('thresholds',fontsize=font_size)
        plt.ylabel('f1_score',fontsize=font_size)
        for i in range(len(xsv_files)):
            xsv = xsv_files[i]
            thresholds = []
            f1_scores = []
            if xsv.split('.')[-1] == 'tsv':
                with open(xsv, "r") as the_file:
                    content = the_file.readlines()
                    for line in content[1:]:
                        line.strip()
                        threshold = float(line.split('\t')[0])
                        f1_score = float(line.split('\t')[1])
                        thresholds.append(threshold)
                        f1_scores.append(f1_score)
            elif xsv.split('.')[-1] == 'csv':
                dataframe = pd.read_csv(xsv)
                thresholds = dataframe['threshold']
                f1_scores = dataframe['f1_scores']
            plt.plot(thresholds, f1_scores, color=colors[i], linestyle=linestyles[i % 4], label=curve_label[i])
        plt.legend(loc='lower left',fontsize=font_size-10)
        plt.tight_layout()
        fig.savefig(str(logdir) + "/" + curve_name + ".pdf")
        plt.close(fig)


def DrawROC(test_y,test_pred,logdir):
    test_fpr, test_tpr, test_thresholds = metrics.roc_curve(test_y, test_pred, pos_label=1)
    # write ROC raw data
    # with open(str(logdir) + "/best_test_roc.tsv", "w") as the_file:
    #     the_file.write("#thresholds\ttpr\tfpr\n")
    #     for t, tpr, fpr in zip(test_thresholds, test_tpr, test_fpr):
    #         the_file.write("{}\t{}\t{}\n".format(t, tpr, fpr))

    data_dict = {'threshold': test_thresholds, 'tprs': test_tpr, 'fprs': test_fpr}
    dataframe = pd.DataFrame(data_dict)
    dataframe.to_csv(str(logdir) + "/best_test_roc.csv", index=False, sep=',')

    test_auc = metrics.auc(test_fpr, test_tpr)
    fig = plt.figure()
    plt.title('Receiver Operating Characteristic')
    plt.plot(test_fpr, test_tpr, 'b',label='AUC = %0.2f' % test_auc)
    fig.savefig(str(logdir) + "/best_test_roc.pdf")
    plt.close(fig)
    return test_auc

def DrawRecall_Pre_F1(test_y,test_pred,logdir):
    precision, recall, thresholds = metrics.precision_recall_curve(test_y, test_pred,pos_label=1)
    # write P-R raw data
    # with open(str(logdir) + "/pre_recall.tsv", "w") as the_file:
    #     the_file.write("#thresholds\tprecision\trecall\n")
    #     for t, pre, rec in zip(thresholds, precision, recall):
    #         the_file.write("{}\t{}\t{}\n".format(t, pre, rec))

    data_dict = {'threshold': thresholds, 'precision': precision[0:-1], 'recall': recall[0:-1]}
    dataframe = pd.DataFrame(data_dict)
    dataframe.to_csv(str(logdir) + "/pre_recall.csv", index=False, sep=',')

    fig = plt.figure()
    plt.title('Precision-Recall')
    plt.plot(recall, precision, 'b')
    fig.savefig(str(logdir) + "/pre_recall.pdf")
    plt.close(fig)

    fig = plt.figure()
    plt.title('thresholds-TPR')
    plt.plot(thresholds, recall[0:-1], 'b')
    fig.savefig(str(logdir) + "/thresholds_tpr.pdf")
    plt.close(fig)

    f1_scores = []
    for i in range(len(precision)):
        f1_socre = (2*precision[i]*recall[i])/(precision[i]+recall[i])
        f1_scores.append(f1_socre)

    # with open(str(logdir) + "/thresholds_f1_score.tsv", "w") as the_file:
    #     the_file.write("#thresholds\tf1_score\n")
    #     for t, f1 in zip(thresholds, f1_scores):
    #         the_file.write("{}\t{}\n".format(t, f1))

    data_dict = {'threshold': thresholds, 'f1_scores': f1_scores[0:-1]}
    dataframe = pd.DataFrame(data_dict)
    dataframe.to_csv(str(logdir) + "/thresholds_f1_score.csv", index=False, sep=',')

    fig = plt.figure()
    plt.title('thresholds_f1_score')
    plt.plot(thresholds, f1_scores[0:-1], 'b')
    fig.savefig(str(logdir) + "/thresholds_f1_score.pdf")
    plt.close(fig)

    DrawF1score_CDF(precision, recall, logdir)

def DrawF1score_CDF(precision,recall,logdir):
    f1_scores = []
    f1_scores_percents = []
    CDF_X = list(np.linspace(0, 1, num=100))  # f1-score-cdf的横坐标
    for i in range(len(precision)):
        f1_socre = (2*precision[i]*recall[i])/(precision[i]+recall[i])
        f1_scores.append(f1_socre)
    for CDF in CDF_X:
        f1_scores_percents.append(GetPercent_Of_F1_score(f1_scores,CDF))
    fig = plt.figure()
    plt.title('F1score-CDF')
    plt.plot(CDF_X, f1_scores_percents, 'b')
    fig.savefig(str(logdir) + "/F1score-CDF.pdf")
    plt.close(fig)
    # with open(logdir + "/F1score-CDF.tsv", "w") as the_file:
    #     the_file.write("#F1_score\tpercentage\n")
    #     for c, per in zip(CDF_X, f1_scores_percents):
    #         the_file.write("{}\t{}\n".format(c, per))

    data_dict = {'CDF_X': CDF_X, 'f1_scores_percents': f1_scores_percents}
    dataframe = pd.DataFrame(data_dict)
    dataframe.to_csv(str(logdir) + "/F1score-CDF.csv", index=False, sep=',')

def GetPercent_Of_F1_score(f1_scores,CDF):
    num = 0
    for f1_score in f1_scores:
        if f1_score <= CDF:
            num += 1
    percent = float(num)/len(f1_scores)
    return percent

def Draw_ROC_K(similar_rate,truth,logdir):
    sort_similar,sort_truth = similar_truth_sort(similar_rate,truth)
    keylist = [i for i in range(5, len(truth), 5)]
    fpr_my,tpr_my = myself_roc(sort_similar,sort_truth,keylist)
    auc_my = metrics.auc(fpr_my,tpr_my)

    # with open(str(logdir) + "/roc_k.tsv", "w") as the_file:
    #     the_file.write("#k\ttpr\tfpr\n")
    #     for k, tpr, fpr in zip(keylist, tpr_my, fpr_my):
    #         the_file.write("{}\t{}\t{}\n".format(k, tpr, fpr))
    data_dict = {'keylist': keylist, 'tpr_my': tpr_my, 'fpr_my': fpr_my}
    dataframe = pd.DataFrame(data_dict)
    dataframe.to_csv(str(logdir) + "/roc_k.csv", index=False, sep=',')

    fig = plt.figure()
    plt.title('roc_k')
    plt.plot(fpr_my, tpr_my, 'b')
    fig.savefig(str(logdir) + "/roc_k.pdf")
    plt.close(fig)


    # with open(logdir + "/k_recall.tsv", "w") as the_file:
    #     the_file.write("#k\trecall\n")
    #     for k, recall in zip(keylist, tpr_my):
    #         the_file.write("{}\t{}\n".format(k, recall))
    data_dict = {'keylist': keylist, 'tpr_my': tpr_my}
    dataframe = pd.DataFrame(data_dict)
    dataframe.to_csv(str(logdir) + "/k_recall.csv", index=False, sep=',')

    fig = plt.figure()
    plt.title('k_recall')
    plt.plot(keylist, tpr_my, 'b')
    fig.savefig(str(logdir) + "/k_recall.pdf")
    plt.close(fig)

def similar_truth_sort(similar,truth):
    sort_similar = []
    sort_truth = []
    sort_index = np.argsort(-similar) # from max to small
    for i in sort_index:
        sort_similar.append(similar[i])
        sort_truth.append(truth[i])
    return sort_similar,sort_truth

def myself_roc(similar,truth,keylist):
    fpr = []
    tpr = []
    for key in keylist:
        tp = float(0)
        fp = float(0)
        tn = float(0)
        fn = float(0)
        for i in range(key):
            if truth[i] == True:
                tp += 1
            else:
                fp += 1
        for i in range(key,len(similar)):
            if truth[i] == True:
                fn += 1
            else:
                tn += 1
        tpr.append(tp / (tp + fn))
        fpr.append(fp / (fp + tn))
    return fpr,tpr

# 合并多张图到一起
def MergeMultiFig(fig_path_list,outdir):
    imgs = []
    for fig in fig_path_list:
        imgs.append(img.imread(fig))
    plt.figure()
    for i in range(1,len(imgs)+1):
        plt.subplot(1,len(imgs),i)
        plt.imshow(imgs[i-1])
        plt.axis('off') # 不显示坐标轴
    plt.show()
    plt.save(outdir + "merge.png")

# 获取所有文件名，包括子文件夹
def check_file(file_path):
    os.chdir(file_path)
    # print(os.path.abspath(os.curdir))
    all_file = os.listdir()
    files = []
    for f in all_file:
        if os.path.isdir(f):
            files.extend(check_file(file_path+'/'+f))
            os.chdir(file_path)
        else:
            files.append(file_path+'/'+f)
    return files

def heapMapPlot(data,key_list,title,logdir,sexi='Accent'):
    '''
    基于相关性系数计算结果来绘制热力图
    '''
    colormap=plt.cm.RdBu
    data=np.array(data)
    fig,ax=plt.subplots(figsize=(12,12))
    sns.heatmap(pd.DataFrame(np.round(data,4),columns=key_list,index=key_list),annot=True,vmax=1,vmin=0,
                xticklabels=True,yticklabels=True,square=True,cmap=sexi)  #"YlGnBu"
    plt.title(title)
    plt.savefig(str(logdir) + "/heat.pdf")
    
# 绘制柱状图
# draw_dict:{method:metrics}
def draw_histogram_pic(draw_dict,methods,labels,fig_name,width,fontsize,base_size,pos,logdir):
    os.makedirs(logdir, exist_ok=True)
    plt.style.use('bmh')
    # plt.style.use('grayscale')
    # plt.xkcd() # 比较好玩的风格
    # 图表风格选择
    style = ['bmh', 'classic', 'dark_background', 'fast', 'fivethirtyeight', 
    'ggplot', 'grayscale', 'seaborn-bright', 'seaborn-colorblind', 
    'seaborn-dark-palette', 'seaborn-dark', 'seaborn-darkgrid', 
    'seaborn-deep', 'seaborn-muted', 'seaborn-notebook', 'seaborn-paper', 
    'seaborn-pastel', 'seaborn-poster', 'seaborn-talk', 'seaborn-ticks', 
    'seaborn-white', 'seaborn-whitegrid', 'seaborn', 'Solarize_Light2', 
    'tableau-colorblind10', '_classic_test']
    # 配色方案选择
    colors = ['#0072BD','#D95319','#EDB120','#C82423','#4DBEEE','#4DBEEE']
    # colors = ['#8ECFC9','#FFBE7A','#FA7F6F','#82B0D2','#BEB8DC','#E7DAD2']
    # colors = ['#2878B5','#9AC9D8','#F8AC8C','#C82423','#FF8884','#4DBEEE']
    # colors = ['#2F7FC1','#96C37D','#F3D266','#D8383A','#C497B2','#4DBEEE'] # 彩色
    # colors = ['#ffffff','#ffffff','#ffffff','#a2a2a2','#4e4e4e','#000000'] # 灰度
    patterns = ['-','/','o', 'x', '\\', '+', 'x', '*', '+', 'O', '.', '-', '\\','+']
    fig = plt.figure(dpi=300,figsize=(1.618*base_size,base_size))
    # 构造x轴刻度标签、数据
    m_list = [draw_dict[methods[i]] for i in range(len(methods))]
    
    # 四组数据
    ax1 = plt.subplot(111)
    x = np.arange(len(labels))  # x轴刻度标签位置
    width = width  # 柱子的宽度
    zoom = 1 # 柱子宽度缩放
    bet = 0.02 # 柱子的间隔
    linewidth = 1.0 # 柱子边框粗细
    # plt.grid(True, lw=linewidth-0.5, ls='-', c='black', axis='y') # 绘制网格axis='both/x/y'
    # 计算每个柱子在x轴上的位置，保证x轴刻度标签居中,自定义color
    for i,m in enumerate(m_list):
        if 'tau' in methods[i]:
            methods[i] = r"$\tau$" + methods[i].split('tau')[1]
        plt.bar(x + i*width+i*bet, m, zoom*width, label=methods[i],color=colors[i],hatch=patterns[i],edgecolor='black',linewidth=linewidth)
    
    loc='upper right'
    yLabel = 'Values'
    xLabel = 'Metrics'
    # plt.ylabel(yLabel,fontsize=fontsize,labelpad=15, fontproperties = 'Times New Roman')
    # plt.xlabel(xLabel,fontsize=fontsize,labelpad=15, fontproperties = 'Times New Roman')
    # fig.autofmt_xdate() # 倾斜
    plt.xticks(ticks=x + pos*width+pos*bet,labels=labels, size=fontsize, fontproperties = 'Times New Roman')

    #设置坐标刻度值的大小以及刻度值的字体
    plt.tick_params(labelsize=fontsize)
    labels = ax1.get_xticklabels() + ax1.get_yticklabels()
    [label.set_fontname('Times New Roman') for label in labels]
    if 'avg' in fig_name:
        if fig_name == 'Micro_PearsonrSim_avg_filter_cve':
            plt.ylim(0.0,0.9)
        else:
            plt.ylim(0.0,0.85)
        plt.legend(bbox_to_anchor=(0.0,0.5,1.0,0.5), loc="upper center",mode="expand", borderaxespad=0, ncol=5, fontsize=fontsize, 
               prop={'family':'Times New Roman','size':fontsize})
    else:
        plt.legend(loc=loc, fontsize=fontsize)
    fig.savefig(os.path.join(logdir,fig_name+'.pdf'),dpi=600,format='pdf',bbox_inches='tight') # 再用visio另存为emf
    plt.close(fig)
    
def draw_all_histogram_pic():
    width_dict = {
        2:0.15,
        3:0.15,
        4:0.12,
        5:0.1
    }
    fontsize_dict = {
        2:30,
        3:30,
        4:30,
        5:30
    }
    base_size_dict = {
        2:10,
        3:10,
        4:10,
        5:10
    }
    pos_dict = {
        2:0.5,
        3:1,
        4:1.5,
        5:2
    }
    # feature_metrics
    draw_dict = {
        'BinCola':[0.9723,0.9741,0.3390,0.6820,0.4914],
        'TikNib':[0.9203,0.9228,0.1122,0.2440,0.1805],
        'NoAttention':[0.8983,0.8896,0.1090,0.2590,0.1923],
        'NoDL':[0.7687,0.7881,0.1000,0.1870,0.1471],
    }
    labels = ['AUC','AP','Recall@1','Recall@5','MRR']
    fig_name = 'feature_metrics'
    main_folder = '/home/passwd123/JiangS/CodeTransformer/BCSA/IFAttnCon_Linux/ContrastiveLearning/core/results'
    logdir = os.path.join(main_folder,'curve/metrics')
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)
    # Hyperparameters_metrics
    draw_dict = {
        'n-5':[0.9689,0.9678,0.2310,0.5530,0.3723],
        'n-10':[0.9710,0.9715,0.278,0.6140,0.4301],
        'n-20':[0.9717,0.9733,0.3290,0.6590,0.4762],
        'n-25':[0.9723,0.9741,0.3390,0.6820,0.4914],
        'n-30':[0.9715,0.9741,0.3320,0.6590,0.4771],
    }
    fig_name = 'Hyperparameters_metrics'
    labels = ['AUC','AP','Recall@1','Recall@5','MRR']
    n = 5
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)
    # Outtype_metrics
    draw_dict = {
        'mean':[0.9717,0.9733,0.3290,0.6590,0.4762],
        'sum':[0.9714,0.9734,0.3300,0.6610,0.4748],
        'last':[0.9703,0.9713,0.2630,0.6080,0.4163],
    }
    fig_name = 'Outtype_metrics'
    labels = ['AUC','AP','Recall@1','Recall@5','MRR']
    n = 3
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)

    # temper_metrics
    draw_dict = {
        'tau-0.05':[0.9621,0.9600,0.2410,0.5810,0.3948],
        'tau-0.1':[0.9723,0.9741,0.3390,0.6820,0.4914],
        'tau-0.5':[0.9639,0.9629,0.2350,0.5140,0.3688],
        'tau-0.9':[0.9538,0.9471,0.1740,0.4310,0.2990],
    }
    fig_name = 'temper_metrics'
    labels = ['AUC','AP','Recall@1','Recall@5','MRR']
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)
    
    # O0-O3 vul_patch
    draw_dict = {
        'BinCola':[0.666667,0.564688,0.432777,0.388982],
        # 'Siamese':[0.340580,0.518125,0.416094,0.340622],
        'PalmTree':[0.688406,0.514688,0.385672,0.362069],
        'jTrans':[0.681159,0.506875,0.385182,0.351976],
        'BinXray':[0.289855,0.302500,0.216879,0.221194],
    }
    fig_name = 'vul_patch'
    labels = ['func_acc','all_acc','patch_recall','vulner_recall']
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)

    # avg_vul_patch
    draw_dict = {
        'BinCola':[0.564022,0.649387,0.579306,0.585863],
        # 'Siamese':[0.376396,0.473345,0.494898,0.381834],
        'PalmTree':[0.643193,0.685103,0.680018,0.568896],
        'jTrans':[0.530692,0.603798,0.568517,0.533071],
        'BinXray':[0.396003,0.545807,0.527374,0.499351],
    }
    fig_name = 'avg_vul_patch'
    labels = ['func_acc','all_acc','patch_recall','vulner_recall']
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)
    
    # avg_filter_vul_patch
    draw_dict = {
        'BinCola':[0.655727,0.694337,0.597204,0.626427],
        # 'Siamese':[0.434334,0.491919,0.450583,0.399580],
        'PalmTree':[0.674185,0.707717,0.662404,0.583580],
        'jTrans':[0.585096,0.642978,0.546427,0.575773],
        'BinXray':[0.477400,0.627148,0.541148,0.586230],
    }
    fig_name = 'avg_filter_vul_patch'
    labels = ['func_acc','all_acc','patch_recall','vulner_recall']
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)

    # Micro_PearsonrSim_avg_filter_vul_patch
    draw_dict = {
        'BinCola':[0.572917,0.672676,0.538854,0.544028],
        'PalmTree':[0.515625,0.645534,0.509359,0.532542],
        'jTrans':[0.455729,0.550537,0.430800,0.459035],
        'BinXray':[0.294271,0.442779,0.342314,0.374809],
    }
    fig_name = 'Micro_PearsonrSim_avg_filter_vul_patch'
    labels = ['func_acc','all_acc','vulner_recall','patch_recall']
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)
    
    # O0-O3 CVE
    draw_dict = {
        'BinCola':[0.473661,0.406250,0.780928,0.141264],
        # 'Siamese':[0.440625,0.343750,0.609107,0.258364],
        'PalmTree':[0.431250,0.406250,0.751718,0.084572],
        'jTrans':[0.429911,0.406250,0.750000,0.083643],
        'BinXray':[0.333482,0.156250,0.573883,0.073420],
    }
    fig_name = 'cve'
    labels = ['cve_acc','cve_ver_acc','cve_vulner_recall','cve_patch_recall']
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)
    
    # avg_CVE
    draw_dict = {
        'BinCola':[0.606488,0.650810,0.622233,0.595587],
        # 'Siamese':[0.422871,0.229477,0.389913,0.523910],
        'PalmTree':[0.645054,0.700810,0.595607,0.739313],
        'jTrans':[0.590478,0.603439,0.599228,0.611539],
        'BinXray':[0.515854,0.506614,0.510293,0.582823],
    }
    fig_name = 'avg_cve'
    labels = ['cve_acc','cve_ver_acc','cve_vulner_recall','cve_patch_recall']
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)

    # avg_filter_CVE
    draw_dict = {
        'BinCola':[0.661913,0.751041,0.684161,0.636503],
        # 'Siamese':[0.442670,0.216471,0.421333,0.483122],
        'PalmTree':[0.668981,0.760565,0.621892,0.726056],
        'jTrans':[0.636227,0.685374,0.665302,0.602591],
        'BinXray':[0.614261,0.598980,0.625170,0.626895],
    }
    fig_name = 'avg_filter_cve'
    labels = ['cve_acc','cve_ver_acc','cve_vulner_recall','cve_patch_recall']
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)

    # Micro_PearsonrSim_avg_filter_cve
    draw_dict = {
        'BinCola':[0.572152,0.792683,0.570871,0.573757],
        'PalmTree':[0.551899,0.768293,0.535761,0.572127],
        'jTrans':[0.541772,0.768293,0.547464,0.534637],
        'BinXray':[0.390958,0.463415,0.379714,0.405053],
    }
    fig_name = 'Micro_PearsonrSim_avg_filter_cve'
    labels = ['cve_acc','cve_ver_acc','cve_vulner_recall','cve_patch_recall']
    n = 4
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)

    # 孪生网络对比
    draw_dict = {
        'BinCola':[0.9718,0.9736,0.0742,0.2773,0.1758],
        'Siamese':[0.9644,0.9622,0.0620,0.2048,0.1378]
    }
    fig_name = 'Siamese'
    labels = ['AUC','AP','Recall@1','Recall@5','MRR']
    n = 2
    width = width_dict[n]
    fontsize = fontsize_dict[n]
    base_size = base_size_dict[n]
    pos = pos_dict[n]
    draw_histogram_pic(draw_dict,list(draw_dict.keys()),labels,fig_name,width,fontsize,base_size,pos,logdir)
    

if __name__ == "__main__":
    # 欧几里得距离，余弦相似度计算，实质就是余弦夹角
    # input1 = torch.abs(torch.randn(1,5))
    # input2 = torch.abs(torch.randn(1,5))
    # output = F.pairwise_distance(input1, input2, p=2)
    # output2 = F.cosine_similarity(input1, input2)
    # output3 = cosine_similarity(input1.numpy(),input2.numpy())[0][0]
    # print(input1,input2,output,output2,output3)
    # exit(0)
    
    # 绘制poolsize折线图
    # main_folder = '/home/passwd123/JiangS/CodeTransformer/BCSA/IFAttnCon_Linux/ContrastiveLearning/core/results'
    # logdir = os.path.join(main_folder,'curve/smooth_poolsize')
    # bincola_csv = os.path.join(main_folder,'poolsize_csv/bincola_poolsize.csv')
    # jtrans_csv = os.path.join(main_folder,'poolsize_csv/jtrans_poolsize.csv')
    # palmtree_csv = os.path.join(main_folder,'poolsize_csv/palm_poolsize.csv')
    # font_size = 35
    # Draw_Poolsize_Topk_Polyline([bincola_csv,jtrans_csv,palmtree_csv],
    #             ['BinCola','jTrans','PalmTree'],font_size,logdir)
    # exit(0)

    # 绘制vulner_patch相似度折线图
    # main_folder = '/home/passwd123/JiangS/CodeTransformer/BCSA/IFAttnCon_Linux/ContrastiveLearning/core/results'
    # logdir = os.path.join(main_folder,'curve/vulner_patch')
    # bincola_csv = os.path.join(main_folder,'vulner_patch/x86_64_x86_64_WithFeature-True_WithDL-BinCola.json')
    # jtrans_csv = os.path.join(main_folder,'vulner_patch/x86_64_x86_64_WithFeature-True_WithDL-Jtrans.json')
    # palmtree_csv = os.path.join(main_folder,'vulner_patch/x86_64_x86_64_WithFeature-True_WithDL-Palm.json')
    # binxray_csv = os.path.join(main_folder,'vulner_patch/x86_64_x86_64_WithFeature-False_WithDL-Jtrans.json')
    # font_size = 20
    # Draw_Vul_Patch_Sim_Polyline([bincola_csv,jtrans_csv,palmtree_csv,binxray_csv],
    #             ['BinCola','jTrans','PalmTree','BinXray'],font_size,logdir)
    # exit(0)
    
    # 绘制柱状图
    draw_all_histogram_pic()
    exit(0)


    main_folder = '/home/passwd123/JiangS/CodeTransformer/BCSA/IFAttnCon_Linux/ContrastiveLearning/core/results'
    # features = 'features.txt'
    # att = np.load(os.path.join(main_folder,"att.npy"))
    # f = open(os.path.join(main_folder,"features.txt"),'r')
    # features = f.read().split('\n')[:-1]
    # heapMapPlot(att[0:10,0:10],features[0:10],'att',main_folder)
    # exit(0)
    config_all_list = [
        # "config_gnu_normal_arch_all_type",
        # "config_gnu_normal_arch_arm_mips_type",
        # "config_gnu_normal_arch_x86_arm_type",
        # "config_gnu_normal_arch_x86_mips_type",
        "config_gnu_normal_opti_O0-O3_type",
        "config_gnu_normal_opti_O0toO3_type",
        "config_gnu_normal_opti_O1-O2_type",
        "config_gnu_normal_opti_O1-O3_type",
        "config_gnu_normal_opti_O2-O3_type",
        # "config_gnu_normal_obfus_all_type",
        # "config_gnu_normal_obfus_bcf_type",
        # "config_gnu_normal_obfus_fla_type",
        # "config_gnu_normal_obfus_sub_type",
        # "config_gnu_normal_comp_gcc-clang_type",
    ]

    config_no_obfus_list = [
        # "config_gnu_normal_all_type",
        # "config_gnu_normal_arch_all_type",
        # "config_gnu_normal_arch_arm_mips_type",
        # "config_gnu_normal_arch_x86_arm_type",
        # "config_gnu_normal_arch_x86_mips_type",
        # "config_gnu_normal_opti_O0-O3_type",
        # "config_gnu_normal_opti_O0toO3_type",
        # "config_gnu_normal_opti_O1-O2_type",
        # "config_gnu_normal_opti_O1-O3_type",
        "config_gnu_normal_opti_O2-O3_type",
        "config_gnu_normal_comp_gcc-clang_type"
    ]
    config_obfus_list = [
        "config_gnu_normal_obfus_all_type",
        "config_gnu_normal_obfus_bcf_type",
        "config_gnu_normal_obfus_fla_type",
        "config_gnu_normal_obfus_sub_type",
    ]
    curve_name_list = [
        'best_test_roc',
        'F1score-CDF',
        'pre_recall',
        'thresholds_f1_score'
    ]
    font_size = 30
    # 单独绘制每个config的结果图
    for config in config_all_list:
        ifattn_folder = main_folder + '/IFAttn_ase18/' + config + '/curve/'
        ifattn_no_att_folder = main_folder + '/IFAttn-No/' + config + '/curve/'
        ifattn_origin_folder = main_folder + '/IFAttn-Origin/' + config + '/curve/'
        tiknib_folder = main_folder + '/tiknib_ase18/' + config + '/curve/'
        gemini_folder = main_folder + '/gemini_result_all/' + config + '/curve/'
        asteria_folder = main_folder + '/Asteria/' + config + '/curve/'
        codee_folder = main_folder + '/codee/' + config + '/curve/'
        bincola_folder = main_folder + '/bincola/CosSim/mean/fusion/' + config + '/curve/'
        jtrans_folder = main_folder + '/jtrans/CosSim/mean/' + config + '/curve/'
        palmtree_folder = main_folder + '/palmtree/CosSim/mean/' + config + '/curve/'
        logdir = main_folder + '/curve/' + config
        for curve_name in curve_name_list:
            print('draw:{}-{}-curve'.format(config,curve_name))
            # Draw_By_csv([dl_folder+curve_name+'.csv',tiknib_folder+curve_name+'.csv'],['IFAttn','TIKNIB'],curve_name,font_size,logdir)
            # Draw_By_tsv([dl_folder+curve_name+'.tsv',tiknib_folder+curve_name+'.tsv'],['IFAttn','TIKNIB'],curve_name,font_size,logdir)
            # 混合的输入格式tsv,csv

            # Draw_By_xsv([ifattn_folder+curve_name+'.tsv',
            #     tiknib_folder+curve_name+'.tsv',
            #     gemini_folder+curve_name+'.csv'],
            #     ['IFAttn','TIKNIB','Gemini'],curve_name,font_size,logdir)
            # Draw_By_xsv([ifattn_folder+curve_name+'.csv',
            #     ifattn_no_att_folder+curve_name+'.csv',
            #     ifattn_origin_folder+curve_name+'.csv'],
            #     ['IFAttn','No-Attn','No-Net'],curve_name,font_size,logdir)
            # Draw_By_xsv([ifattn_folder+curve_name+'.csv',
            #     tiknib_folder+curve_name+'.csv'],
            #     ['IFAttn','TIKNIB'],curve_name,font_size,logdir)
            # Draw_By_xsv([ifattn_folder+curve_name+'.csv',
            #     tiknib_folder+curve_name+'.csv',
            #     gemini_folder+curve_name+'.csv',
            #     asteria_folder+curve_name+'.csv'],
            #     ['IFAttn','TIKNIB','Gemini','Asteria'],curve_name,font_size,logdir)
            Draw_By_xsv([
                bincola_folder+curve_name+'.csv',
                jtrans_folder+curve_name+'.csv',
                palmtree_folder+curve_name+'.csv',
                ],
                ['BinCola','jTrans','PalmTree'],curve_name,font_size,logdir)


    # 汇总所有结果图
    fig_folder = main_folder + '/curve/'
    out_folder = main_folder + '/curve/total/'
    os.makedirs(out_folder,exist_ok=True)
    all_fig_list = check_file(fig_folder)
    for fig in all_fig_list:
        if 'best_test_roc.pdf' in fig or 'pre_recall.pdf' in fig or 'thresholds_f1_score.pdf' in fig:
            target = out_folder + fig.split('config_gnu_normal_')[1].replace('/','_').replace('_','-')
            copyfile(fig, target)
    
    # 汇总所有注意力权重
    # option_dict = {}
    # exist_dict = {}
    # feature_list = []
    # for config in config_all_list:
    #     fig_folder = main_folder + '/IFAttn/' + config + '/attn/'
    #     out_folder = main_folder + '/attn-weight/'
    #     os.makedirs(out_folder,exist_ok=True)
    #     all_fig_list = check_file(fig_folder)
    #     # # 保存所有的注意力权重热力图
    #     # for fig in all_fig_list:
    #     #     if 'multi_att.pdf' in fig:
    #     #         target = out_folder + fig.split('config_gnu_normal_')[1].replace('/','_').replace('_','-').replace('-attn--','-')
    #     #         copyfile(fig, target)
    #     # 汇总所有的注意力权值
        
    #     out_folder = out_folder + '/feature_att/'
    #     os.makedirs(out_folder,exist_ok=True)
    #     data_dict = {'features':[],}
    #     option = '_'.join(config.split('_')[-3:-1])
    #     data_dict[option] = []
    #     option_dict[option] = []
    #     for fig in all_fig_list:
    #         if 'features_att' in fig:
    #             f = open(fig,'r')
    #             data = f.read().split('\n')[:-1]
    #             for line in data:
    #                 feature = line.split(':')[1].split('-')[1]
    #                 weight = line.split(':')[1].split('-')[0]
    #                 data_dict['features'].append(feature)
    #                 data_dict[option].append(weight)
    #                 option_dict[option].append(feature)
    #                 if feature not in feature_list:
    #                     feature_list.append(feature)
    #     dataframe = pd.DataFrame(data_dict)
    #     dataframe.to_csv(os.path.join(out_folder,option + '.csv'), index=False, sep=',')
    # exist_dict['features'] = feature_list
    # for option in option_dict.keys():
    #     option_feature = option_dict[option]
    #     exist_feature = list(np.zeros(len(feature_list)))
    #     for i in range(len(feature_list)):
    #         if feature_list[i] in option_feature:
    #             exist_feature[i] = 1
    #     exist_dict[option] = exist_feature
    # dataframe = pd.DataFrame(exist_dict)
    # dataframe.to_csv(os.path.join(out_folder,'feature_select.csv'), index=False, sep=',')




