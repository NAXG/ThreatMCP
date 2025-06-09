"""威胁书API响应处理模块"""

from typing import Dict, Any, Tuple


class ThreatBookResponseHandler:
    """威胁书API响应处理器"""
    
    # 响应码对照表
    RESPONSE_CODES = {
        0: "成功",
        1: "部分成功",
        2: "没有数据",
        3: "任务进行中",
        4: "未发现报告",
        5: "没有反病毒扫描引擎检测数据",
        6: "URL 下载文件失败",
        7: "URL 下载文件中",
        8: "URL 下载文件上传沙箱失败",
        -1: "权限受限或请求出错",
        -2: "请求无效",
        -3: "请求参数缺失",
        -4: "超出请求限制",
        -5: "系统错误",
        -6: "模型报错",
        -7: "模型问题或回答包括敏感文本",
        -8: "问题和网络安全无关，拒绝回答",
        -9: "超出当前模型能力覆盖范围",
        -10: "请求tokens长度过长，超过模型限制"
    }
    
    # 详细错误信息对照表
    VERBOSE_MSG_DETAILS = {
        "No Data": "查询成功，但查询的资源没有相关数据",
        "In Progress": "报告正在生成中，请稍后查询",
        "No Report Found": "未发现报告，建议将该样本进行上传以获取报告信息",
        "NO_AUTHORITY": "隐私样本，无法返回报告信息，建议将该样本进行上传",
        "No MultiEngines Data": "没有反病毒扫描引擎检测数据，建议将该样本进行上传",
        "URL Download Fail": "URL下载文件失败，请重新提交扫描URL请求",
        "URL Downloading": "URL下载文件中，请稍等",
        "URL Upload Sandbox Fail": "URL下载文件上传沙箱失败",
        "Invalid Account Status": "账户状态无效，请联系微步在线工作人员",
        "Invalid Access IP": "无效的访问IP，请检查IP白名单设置",
        "Invalid API Key": "无效的API key，请检查APIKey是否正确",
        "Invalid Key Status": "API key状态无效，APIKey被禁用",
        "No Access to API Method": "没有访问接口权限，请检查API接口授权状态",
        "Expired API Key": "API Key过期，请联系微步在线产品对接人",
        "Empty File": "上传空文件，请确认是否选择了错误的文件",
        "File Size Too Large": "上传文件过大，请不要超过100M",
        "File Name Too Long": "上传文件名过长，请不要超过128字节",
        "URL Too Large": "URL下载文件过大",
        "Invalid API Method": "无效的API接口，请确认调用的接口是否存在",
        "Frequent Limitation": "触发访问频次限制，请求超过了接口每分钟的默认限速频率",
        "BeyondLimitation": "超出访问限制，已超出接口授权限制",
        "System Error": "系统错误，请联系微步在线产品对接人",
        "Model Error": "模型报错，请检查请求参数和格式",
        "Response Contains Restricted Content": "问题或回答包括敏感文本，拒绝回答",
        "Query Not Relevant to Cybersecurity, Declined": "问题和网络安全无关，拒绝回答",
        "Query Beyond Model Capabilities": "超出当前模型能力覆盖范围",
        "Input Token Limit Exceeded": "请求tokens长度过长，超过模型限制"
    }
    
    @classmethod
    def check_response(cls, result: Dict[str, Any]) -> Tuple[bool, str]:
        """
        检查API响应状态
        
        Args:
            result: API响应结果
            
        Returns:
            Tuple[bool, str]: (是否成功, 错误信息)
        """
        response_code = result.get("response_code")
        verbose_msg = result.get("verbose_msg", "")
        
        # 成功状态
        if response_code == 0:
            return True, ""
        
        # 部分成功状态
        if response_code == 1:
            # 检查是否有特殊的部分成功信息
            if "Beyond Limitation" in verbose_msg:
                return True, f"⚠️ 部分成功: {verbose_msg}"
            elif "Invalid data format" in verbose_msg:
                return True, f"⚠️ 部分成功: {verbose_msg}"
            else:
                return True, f"⚠️ 部分成功: {verbose_msg}"
        
        # 获取错误描述
        error_desc = cls.RESPONSE_CODES.get(response_code, f"未知错误码: {response_code}")
        
        # 获取详细错误信息
        detailed_msg = ""
        if verbose_msg:
            # 检查是否有已知的详细错误信息
            for key, detail in cls.VERBOSE_MSG_DETAILS.items():
                if key in verbose_msg:
                    detailed_msg = detail
                    break
            
            if not detailed_msg:
                detailed_msg = verbose_msg
        
        # 构建完整错误信息
        if detailed_msg:
            error_message = f"{error_desc}: {detailed_msg}"
        else:
            error_message = error_desc
        
        return False, error_message
    
    @classmethod
    def format_error_message(cls, result: Dict[str, Any]) -> str:
        """
        格式化错误信息
        
        Args:
            result: API响应结果
            
        Returns:
            str: 格式化的错误信息
        """
        is_success, error_msg = cls.check_response(result)
        
        if is_success:
            if error_msg:  # 部分成功的情况
                return error_msg
            else:
                return ""
        else:
            return f"❌ 查询失败: {error_msg}"
    
    @classmethod
    def get_success_icon(cls, response_code: int) -> str:
        """
        根据响应码获取状态图标
        
        Args:
            response_code: 响应码
            
        Returns:
            str: 状态图标
        """
        if response_code == 0:
            return "✅"
        elif response_code == 1:
            return "⚠️"
        elif response_code in [2, 3, 4]:
            return "ℹ️"
        else:
            return "❌"
