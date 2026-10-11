#!/bin/bash
# -*- coding: utf-8 -*-
# JScanner2 专用扫描脚本 - Linux纯净版 (支持内存熔断续跑 + 日志归档)
# 核心：Python所有输出直接打印到控制台，实时可见
# 特性：自动监控内存溢出生成的任务文件并接力运行

# ===================== 配置区 =====================
PYTHON_CMD="main.py"
BASE_PYTHON_ARGS="-asia -fp -fs"
# 默认初始深度 (仅用于第一轮主任务)
INITIAL_HEIGHT=5

# --- 📁 文件夹配置 ---
OVERFLOW_DIR="./Overflow_Queue"
LOG_DIR="./logs"
RESULT_DIR="./Result"

# --- 📄 文件路径配置 ---
LOG_FILE="${LOG_DIR}/scan_run_log.log"
DONE_URL_FILE="${LOG_DIR}/scan_done_urls.txt"
FAIL_URL_FILE="${LOG_DIR}/scan_fail_urls.txt"

# --- ❤️ 心跳看门狗参数（可被环境变量覆盖）---
STALL_TIMEOUT=${STALL_TIMEOUT:-180}      # 连续多少秒无“真进展”判定卡死
CHECK_INTERVAL=${CHECK_INTERVAL:-5}      # 看门狗轮询间隔
MAX_RETRY=${MAX_RETRY:-3}                # 卡死后同一URL最多续跑重试次数
START_GRACE=${START_GRACE:-60}           # 启动宽限：心跳未出现时给多少秒
MAX_RUN_SECONDS=${MAX_RUN_SECONDS:-0}    # 单次运行总时长硬上限(0=不限制)
HEARTBEAT_FILE="${RESULT_DIR}/heartbeat.json"
# =================================================

# 初始化所有目录
mkdir -p "${RESULT_DIR}" "${OVERFLOW_DIR}" "${LOG_DIR}"
# 初始化日志文件
touch "${LOG_FILE}" "${DONE_URL_FILE}" "${FAIL_URL_FILE}"

echo -e "===== 扫描开始时间: $(date '+%Y-%m-%d %H:%M:%S') =====" >> "${LOG_FILE}"

# ===================== 处理管道输入/参数输入 =====================
URL_FILE=""
if [ -p /dev/stdin ]; then
    read -r URL_FILE
elif [ $# -eq 1 ]; then
    URL_FILE="$1"
else
    echo -e "\033[31m❌ 错误：请使用正确方式运行！\033[0m"
    echo -e "\033[32m✅ 方式1: echo urls.txt | $0\033[0m"
    echo -e "\033[32m✅ 方式2: $0 urls.txt\033[0m"
    exit 1
fi

# 校验文件是否存在
if [ ! -f "${URL_FILE}" ]; then
    echo -e "\033[31m❌ 错误：URL文件【${URL_FILE}】不存在！\033[0m"
    exit 1
fi

# ===================== Linux专属Python配置与检查 =====================
PYTHON_EXE="python3"
if ! command -v "${PYTHON_EXE}" &> /dev/null; then
    echo -e "\033[31m❌ 错误：未找到python3！\033[0m"
    exit 1
fi

# 检查 psutil 是否安装
${PYTHON_EXE} -c "import psutil" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "\033[33m⚠️  检测到未安装 psutil，正在尝试自动安装...\033[0m"
    pip3 install psutil >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "\033[31m❌ 自动安装 psutil 失败，请手动执行: pip3 install psutil\033[0m"
        exit 1
    fi
fi

# ===================== 读取有效URL =====================

# ===================== 定义扫描核心函数 =====================
get_last_beat() {
    [ -f "${HEARTBEAT_FILE}" ] || { echo 0; return; }
    jq -r '.last_beat_epoch // 0' "${HEARTBEAT_FILE}" 2>/dev/null \
      || ${PYTHON_EXE} -c "import json;print(json.load(open('${HEARTBEAT_FILE}')).get('last_beat_epoch',0))" 2>/dev/null \
      || echo 0
}

kill_group() {   # 连 chromium 一起杀：负号=杀整个进程组
    kill -9 -"$1" 2>/dev/null
    kill -9 "$1" 2>/dev/null
}

run_python_scan() {
    local target_url="$1" scan_height="$2" current_idx="$3" total_count="$4" is_overflow_task="$5"
    local prefix="[${current_idx}/${total_count}]"
    if [ "$is_overflow_task" == "true" ]; then prefix="[🔥溢出接力]"; fi
    echo -e "\033[36m=====================================================\033[0m"
    echo -e "\033[32m▶️  ${prefix} 启动扫描: ${target_url} (深度: ${scan_height})\033[0m"

    setsid ${PYTHON_EXE} -u ${PYTHON_CMD} --url "${target_url}" -H "${scan_height}" ${BASE_PYTHON_ARGS} &
    local child_pid=$!
    local start_ts=$(date +%s)

    while kill -0 "${child_pid}" 2>/dev/null; do
        sleep "${CHECK_INTERVAL}"
        local now=$(date +%s)

        if [ "${MAX_RUN_SECONDS}" -gt 0 ] && [ $((now - start_ts)) -gt "${MAX_RUN_SECONDS}" ]; then
            echo "[$(date '+%F %T')] 🛑 超过总时长上限 $((now-start_ts))s，强制停止: ${target_url}" >> "${LOG_FILE}"
            kill_group "${child_pid}"; wait "${child_pid}" 2>/dev/null; return 125
        fi

        local last=$(get_last_beat)
        if [ "${last}" = "0" ]; then
            if [ $((now - start_ts)) -gt "${START_GRACE}" ]; then
                echo "[$(date '+%F %T')] 🛑 启动 ${START_GRACE}s 仍无心跳，判定启动卡死: ${target_url}" >> "${LOG_FILE}"
                kill_group "${child_pid}"; wait "${child_pid}" 2>/dev/null; return 124
            fi
            continue
        fi

        local stall=$(awk "BEGIN{print int(${now} - ${last})}")
        if [ "${stall}" -gt "${STALL_TIMEOUT}" ]; then
            echo "[$(date '+%F %T')] ⏱️ 心跳停滞 ${stall}s > ${STALL_TIMEOUT}s，判定卡死，杀进程组后续跑: ${target_url}" >> "${LOG_FILE}"
            echo -e "\033[31m⏱️  停滞 ${stall}s，kill -9 进程组 ${child_pid} → 断点续传重启\033[0m"
            kill_group "${child_pid}"; wait "${child_pid}" 2>/dev/null; return 124
        fi
    done

    wait "${child_pid}"; return $?
}

# 卡死(124/125)→ 续跑重试；成功(0)→ DONE；其余非0→ FAIL
run_with_recovery() {
    local url="$1" height="$2" idx="$3" total="$4" overflow="$5"
    local attempt=0 rc
    while true; do
        attempt=$((attempt + 1))
        run_python_scan "${url}" "${height}" "${idx}" "${total}" "${overflow}"
        rc=$?
        if { [ ${rc} -eq 124 ] || [ ${rc} -eq 125 ]; } && [ ${attempt} -lt ${MAX_RETRY} ]; then
            echo -e "\033[33m🔁 第 ${attempt} 次卡死，断点续传重启同一 URL: ${url}\033[0m"
            sleep 2
            continue
        fi
        return ${rc}
    done
}

# ===================== 阶段一：主URL列表扫描 =====================
echo -e "\033[36m🚀 [阶段一] 开始处理主任务列表（热加载模式：实时读取 ${URL_FILE}）...\033[0m"

CURRENT_NUM=0
while true; do
    # 每轮循环重新读取文件，支持运行中追加新 URL
    ALL_URLS=($(grep -v "^#" "${URL_FILE}" | sed '/^[[:space:]]*$/d' | awk '{$1=$1};1' | sort -u))

    # 找出下一个未完成的 URL
    NEXT_URL=""
    for CANDIDATE in "${ALL_URLS[@]}"; do
        if ! grep -qx "${CANDIDATE}" "${DONE_URL_FILE}" && ! grep -qx "${CANDIDATE}" "${FAIL_URL_FILE}"; then
            NEXT_URL="${CANDIDATE}"
            break
        fi
    done

    # 全部完成，退出主循环
    if [ -z "${NEXT_URL}" ]; then
        if [ ${#ALL_URLS[@]} -eq 0 ]; then
            echo -e "\033[31m❌ 错误：URL文件中无有效URL！\033[0m"
        fi
        break
    fi

    CURRENT_NUM=$((CURRENT_NUM + 1))
    TOTAL_URL=${#ALL_URLS[@]}
    TARGET_URL="${NEXT_URL}"
    run_with_recovery "${TARGET_URL}" "${INITIAL_HEIGHT}" "${CURRENT_NUM}" "${TOTAL_URL}" "false"
    _rc=$?
    if [ ${_rc} -eq 0 ]; then
        echo "${TARGET_URL}" >> "${DONE_URL_FILE}"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: ${TARGET_URL} (Depth:${INITIAL_HEIGHT})" >> "${LOG_FILE}"
        echo -e "\033[32m✅ 扫描结束: ${TARGET_URL}\033[0m"
    else
        echo "${TARGET_URL}" >> "${FAIL_URL_FILE}"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAILED(rc=${_rc}, 重试${MAX_RETRY}次仍失败): ${TARGET_URL}" >> "${LOG_FILE}"
        echo -e "\033[31m❌ 扫描异常/反复卡死: ${TARGET_URL}\033[0m"
    fi
done

# ===================== 阶段二：处理内存溢出生成的临时任务 =====================
echo -e "\033[36m=====================================================\033[0m"
echo -e "\033[35m🔄 [阶段二] 检查内存熔断队列 (Overflow_Queue)...\033[0m"

while true; do
    # 查找溢出文件，按文件名排序
    OVERFLOW_FILES=($(ls "${OVERFLOW_DIR}"/overflow_depth_*.txt 2>/dev/null | sort))

    if [ ${#OVERFLOW_FILES[@]} -eq 0 ]; then
        echo -e "\033[32m✨ 队列清空！没有检测到待处理的溢出任务。\033[0m"
        break
    fi

    echo -e "\033[35m📦 发现 ${#OVERFLOW_FILES[@]} 个溢出文件，开始接力处理...\033[0m"

    for FILE_PATH in "${OVERFLOW_FILES[@]}"; do
        if [ ! -f "${FILE_PATH}" ]; then continue; fi

        FILENAME=$(basename "${FILE_PATH}")

        # 从文件名提取剩余深度
        REMAINING_HEIGHT=$(echo "${FILENAME}" | grep -oP '(?<=depth_)\d+')

        if [ -z "${REMAINING_HEIGHT}" ]; then
            echo -e "\033[31m❌ 错误：无法从文件名解析深度: ${FILENAME}，移至error目录\033[0m"
            mkdir -p "${OVERFLOW_DIR}/error"
            mv "${FILE_PATH}" "${OVERFLOW_DIR}/error/"
            continue
        fi

        echo -e "\033[33m📂 读取文件: ${FILENAME} | 接力深度: ${REMAINING_HEIGHT}\033[0m"

        COUNT_IN_FILE=$(wc -l < "${FILE_PATH}")
        CUR_IDX=0

        # 逐行读取文件中的URL
        while read -r SUB_URL; do
            if [ -z "${SUB_URL}" ]; then continue; fi
            CUR_IDX=$((CUR_IDX + 1))

            # 接力扫描
            run_python_scan "${SUB_URL}" "${REMAINING_HEIGHT}" "${CUR_IDX}" "${COUNT_IN_FILE}" "true"

        done < "${FILE_PATH}"

        # 处理完后删除文件
        rm "${FILE_PATH}"
        echo -e "\033[32m🗑️  已完成并删除临时文件: ${FILENAME}\033[0m"
    done
done

# ===================== 扫描完成汇总与通知 =====================
echo -e "\033[36m=====================================================\033[0m"
echo -e "\033[32m🎉 所有主任务及溢出接力任务全部完成！\033[0m"
echo -e "\033[32m📊 统计：主任务URL=${TOTAL_URL} | 成功=$(wc -l < "${DONE_URL_FILE}") | 失败=$(wc -l < "${FAIL_URL_FILE}")\033[0m"
echo -e "\033[32m📝 日志归档: ${LOG_DIR}\033[0m"
echo -e "===== 扫描结束时间: $(date '+%Y-%m-%d %H:%M:%S') =====" >> "${LOG_FILE}"

# 请替换下面的 YOUR_WEBHOOK_URL
FEISHU_URL="https://open.feishu.cn/open-apis/bot/v2/hook/92159458-e2b8-4722-bb212313213213"
TOTAL_SUCCESS=$(wc -l < "${DONE_URL_FILE}")
END_TIME=$(date '+%Y-%m-%d %H:%M:%S')

JSON_CONTENT=$(cat <<EOF
{
    "msg_type": "text",
    "content": {
        "text": "✅ **JScanner 任务全部完成**\n\n📊 扫描统计：成功 ${TOTAL_SUCCESS} 个URL\n📂 结果目录：Result/\n🕒 结束时间：${END_TIME}\n\n所有内存熔断接力任务均已处理完毕。"
    }
}
EOF
)

curl -X POST -H "Content-Type: application/json" -d "${JSON_CONTENT}" "${FEISHU_URL}" >/dev/null 2>&1
echo -e "\n\033[32m📨 最终通知已发送至飞书。\033[0m"
