# coding:utf-8
import os
import sys
import glob
import time
from optparse import OptionParser
from tqdm import tqdm
# sys.path.insert(0, os.path.join(sys.path[0], ".."))
sys.path.append(".")
from ida_scripts.functype import create_ctags, get_default_type_map
from ida_scripts.functype import update_known_types, update_type_map
from ida_scripts.functype import fetch_type
from ida_scripts.utils import do_multiprocess
from ida_scripts.utils import load_func_data, store_func_data
from ida_scripts.utils import load_cache, store_cache

import logging
import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def extract_func_types(args):
    type_map, bin_name = args
    bin_name, func_data_list = load_func_data(bin_name)
    for func in func_data_list:
        ret_type = fetch_type(type_map, func["ret_type"])
        arg_types = []
        for idx, var_name, t, _ in func["args"]:
            arg_types.append(fetch_type(type_map, t))
        func["abstract_args_type"] = arg_types
        func["abstract_ret_type"] = ret_type
    store_func_data(bin_name, func_data_list)

# 获取单个函数类型特征
def get_func_types(func,cache_dir):
    type_map = load_cache(fname="ctags_cache", cache_dir=cache_dir)
    if type_map:
        ret_type = fetch_type(type_map, func["ret_type"])
        arg_types = []
        for idx, var_name, t, _ in func["args"]:
            arg_types.append(fetch_type(type_map, t))
        func["abstract_args_type"] = arg_types
        func["abstract_ret_type"] = ret_type
    return func


def create_ctags_map(source_list,ctags_dir,cache_dir):
    os.makedirs(ctags_dir, exist_ok=True)
    # create ctags
    if source_list:
        logger.info("creating ctags ...")
        t0 = time.time()
        create_ctags(source_list, ctags_dir)
        logger.info("done. (%0.3fs)", time.time() - t0)

    # create type map
    type_map = load_cache(fname="ctags_cache", cache_dir=cache_dir)
    if not type_map:
        logger.info("creating type map ...")
        t0 = time.time()
        type_map = get_default_type_map()
        update_known_types(type_map)

        for ctags_fname in glob.glob(os.path.join(ctags_dir, "include*.tags")):
            update_type_map(type_map, ctags_fname)

        for ctags_fname in glob.glob(os.path.join(ctags_dir, "[!include]*.tags")):
            update_type_map(type_map, ctags_fname)

        logger.info("done ... %0.3fs", time.time() - t0)
        store_cache(type_map, fname="ctags_cache", cache_dir=cache_dir)
    return type_map


if __name__ == "__main__":
    op = OptionParser()
    op.add_option(
        "--input_list",
        type="str",
        action="store",
        dest="input_list",
        default=r"D:\program_jiang\Pro\BCA\PatchScan\deep_learning\input\done_list_all_all_all_all_all_all.txt",
        help="a file containing a list of input binaries",
    )
    op.add_option(
        "--source_list",
        type="str",
        action="store",
        dest="source_list",
        default=r"D:\program_jiang\Pro\BCA\PatchScan\deep_learning\input\source_list_openssl.txt",
        help="a file containing a list of source directories",
    )
    op.add_option(
        "--ctags_dir",
        type="str",
        action="store",
        dest="ctags_dir",
        default=r"D:\program_jiang\Pro\BCA\PatchScan\feature/ctags",
        help="root directory name of the ctags",
    )
    op.add_option(
        "--cache_dir",
        type="str",
        action="store",
        dest="cache_dir",
        default=r"D:\program_jiang\Pro\BCA\PatchScan\feature\cache",
        help="root directory name of the ctags cache",
    )
    op.add_option(
        "--threshold",
        type="int",
        action="store",
        dest="threshold",
        default=1,
        help="number of binaries to process in parallel",
    )
    op.add_option(
        "--chunk_size",
        type="int",
        action="store",
        dest="chunk_size",
        default=1,
        help="number of binaries to process in each process",
    )
    op.add_option("--force", action="store_true", dest="force")
    (opts, args) = op.parse_args()

    assert opts.input_list and opts.ctags_dir
    type_map = create_ctags_map(opts.source_list,opts.ctags_dir,opts.cache_dir)

    # Add abstracted type data to functions in each binary
    with open(opts.input_list, "r") as f:
        bins = f.read().splitlines()

    t0 = time.time()
    logger.info("Processing %d binaries ...", len(bins))
    bins = list(map(lambda x: (type_map, x), bins))
    # linux 多线程
    do_multiprocess(
        extract_func_types, bins, chunk_size=opts.chunk_size, threshold=opts.threshold
    )
    # for bin in tqdm(bins):
    #     extract_func_types(bin)
    logger.info("done. (%0.3fs)", (time.time() - t0))

    # Below code exist is not used for now.
#    t0 = time.time()
#    func_cnt = 0
#    for i in range(0, len(bins), opts.chunk_size):
#        logger.info("Processing %d/%d binaries ...", i, len(bins))
#        args = do_multiprocess(load_func_data,
#                               bins[i:i+opts.chunk_size],
#                               chunk_size=1)
#        # Do not want to share large type_mapping dictionary, so that process it
#        # sequentially
#        args = make_functype_abstract(type_map, args)
#        args = list(filter(lambda x: x and x[1], args))
#        do_multiprocess(store_func_data_wrapper, args, chunk_size=1)
#    logger.info("done. (%0.3fs)", (time.time() - t0))