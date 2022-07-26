# coding:utf-8
# 相似度计算方法

import numpy as np
from scipy.stats import pearsonr


class SimCal():
	def __init__(self,vul=np.array([1,1]),tar=np.array([1,1])) -> None:
		self.v_t_eculid = self.eculidDisSim(vul,tar)
		self.v_t_cos = self.cosSim(vul,tar)
		self.v_t_pearsonr = self.pearsonrSim(vul,tar)
		self.v_t_manhattan = self.manhattanDisSim(vul,tar)
		self.v_t_dict = {
			'EculidDisSim':self.v_t_eculid,
			'CosSim':self.v_t_cos,
			'PearsonrSim':self.v_t_pearsonr,
			'ManhattanDisSim':self.v_t_manhattan,
		}
		
	def eculidDisSim(self,x,y):
		'''
		欧几里得距离，值越大，差距越大
		一般采用以下公式进行转换规约到(0, 1]之间：距离越小，相似度越大
		1 / (1 + d)
		'''
		return np.round(1.0/(1.0+np.sqrt(sum(pow(a-b,2) for a,b in zip(x,y)))),9)

	def cosSim(self,x,y):
		'''
		余弦相似度，值越大，越相似 [-1,1]
		'''
		tmp=np.sum(x*y)
		non=np.linalg.norm(x)*np.linalg.norm(y)
		return np.round(tmp/float(non),9)

	def pearsonrSim(self,x,y):
		'''
		皮尔森线性相关系数，值越大，越相关 [-1,1]
		'''
		return np.round(pearsonr(x,y)[0],9)

	def manhattanDisSim(self,x,y):
		'''
		曼哈顿距离，值越大，差距越大
		一般采用以下公式进行转换规约到(0, 1]之间：距离越小，相似度越大
		1 / (1 + d)
		'''
		return np.round(1.0/(1.0+sum(abs(a-b) for a,b in zip(x,y))),9)

if __name__ == "__main__":
	# a = np.random.uniform(10,20,3)
	# b = np.random.uniform(10,20,3)
	a = np.array([1,2,3])
	b = np.array([1,2,3])
	sim = SimCal(a,b)
	print(a,b,sim.v_t_dict)
