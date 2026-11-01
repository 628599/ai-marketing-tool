"""AI 营销与传播全链路助手 —— 单文件版（含登录门）

部署：把这个文件整个覆盖到仓库根目录的 app.py，然后在 Streamlit Cloud 的
Settings → Secrets 里填 DEEPSEEK_API_KEY / APP_USERNAME / APP_PASSWORD。
登录界面、记住我、SSO 切换全都在本文件里，不依赖其它 .py 文件。

配置项（全部写在 Secrets）：
    DEEPSEEK_API_KEY   必需，DeepSeek 的 API Key
    APP_USERNAME       可选，默认 admin
    APP_PASSWORD       必需，登录密码
    AUTH_COOKIE_SECRET 可选，记住我 token 的签名密钥；不填则由 APP_PASSWORD 派生
    ALLOWED_EMAILS     可选，SSO 模式下的邮箱白名单（逗号分隔）
    [auth]             可选，存在即自动切换为 OIDC 单点登录
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

import streamlit as st
from openai import OpenAI

# ==================== 常量 ====================
MAX_ATTEMPTS = 5      # 连续失败多少次锁定当前会话
REMEMBER_DAYS = 7     # 「记住我」有效期（天）
TOKEN_PARAM = "s"     # token 的 URL 参数名

# set_page_config 必须是第一个 st 命令
st.set_page_config(page_title="AI 营销与传播助手", page_icon="🚀", layout="wide")


# ==================== 1. 配置读取 ====================
def get_secret(name: str, default: str | None = None) -> str | None:
    """安全读取 secrets：缺配置返回默认值，而不是抛异常让整页崩掉。"""
    try:
        return st.secrets[name]
    except Exception:
        return default


def _secret_section(name: str) -> dict:
    try:
        return dict(st.secrets[name])
    except Exception:
        return {}


# ==================== 2. 「记住我」token ====================
def _signing_key() -> bytes:
    raw = get_secret("AUTH_COOKIE_SECRET") or get_secret("APP_PASSWORD") or "default-key"
    return hashlib.sha256(f"ai-marketing-tool::auth::{raw}".encode()).digest()


def issue_token(user: str, days: int = REMEMBER_DAYS) -> str:
    """签发 <用户名>|<过期时间戳>|<HMAC> 的 base64url token。"""
    expires_at = int(time.time()) + days * 86400
    payload = f"{user}|{expires_at}"
    sig = hmac.new(_signing_key(), payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload.encode() + b"|" + sig).decode().rstrip("=")


def verify_token(token: str) -> str | None:
    """校验 token：签名错误或已过期返回 None，成功返回用户名。"""
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode())
        payload, sig = raw.rsplit(b"|", 1)
        expected = hmac.new(_signing_key(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):  # 定长比较，防时序攻击
            return None
        user, expires_at = payload.decode().rsplit("|", 1)
        if int(expires_at) < time.time():
            return None
        return user
    except Exception:
        return None


def _drop_token_param() -> None:
    try:
        if TOKEN_PARAM in st.query_params:
            del st.query_params[TOKEN_PARAM]
    except Exception:
        pass


def _remember_token_ok() -> bool:
    try:
        token = st.query_params.get(TOKEN_PARAM)
    except Exception:
        return False
    if not token:
        return False
    user = verify_token(token)
    if not user:
        _drop_token_param()
        return False
    _mark_authenticated(user)
    return True


# ==================== 3. 会话状态 ====================
def _mark_authenticated(user: str) -> None:
    st.session_state["authed"] = True
    st.session_state["login_user"] = user
    st.session_state["login_attempts"] = 0


def current_user() -> str:
    return st.session_state.get("login_user", "")


def logout() -> None:
    """退出登录：清会话、清 token，SSO 模式下同时登出身份提供方。"""
    for key in ("authed", "login_user", "login_attempts", "last_script"):
        st.session_state.pop(key, None)
    _drop_token_param()
    if _oidc_configured():
        try:
            st.logout()
        except Exception:
            pass
    st.rerun()


# ==================== 4. 登录界面 ====================
def _render_login_shell(title: str, subtitle: str):
    st.markdown(
        """
        <style>
          /* 未登录时隐藏侧边栏，避免提前暴露功能结构 */
          [data-testid="stSidebar"] {display: none;}
          .login-card {text-align: center; padding-bottom: .5rem;}
          .login-card h1 {font-size: 1.9rem; margin-bottom: .2rem;}
          .login-card p {color: #8a8f98; margin-top: 0; font-size: .9rem;}
        </style>
        """,
        unsafe_allow_html=True,
    )
    _left, mid, _right = st.columns([1, 1.2, 1])
    with mid:
        st.markdown(
            f"""
            <div class="login-card">
              <h1>{title}</h1>
              <p>{subtitle}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return mid


# 没配 Secrets 时使用的默认登录口令（这样即使 Secrets 没填，登录页也能正常工作）
DEFAULT_PASSWORD = "123456"
DEFAULT_USERNAME = "admin"


def _password_login() -> bool:
    if st.session_state.get("login_attempts", 0) >= MAX_ATTEMPTS:
        _render_login_shell("🚀 AI 营销与传播助手", "内部演示系统")
        st.error(f"连续 {MAX_ATTEMPTS} 次登录失败，当前会话已锁定。刷新页面可重新尝试。")
        st.stop()

    mid = _render_login_shell("🚀 AI 营销与传播助手", "内部演示系统 · 请使用授权账号登录")

    with mid:
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("账号", placeholder="请输入账号")
            password = st.text_input("密码", type="password", placeholder="请输入密码")
            remember = st.checkbox(f"记住我 {REMEMBER_DAYS} 天（本机保持登录）", value=True)
            submitted = st.form_submit_button("登 录", type="primary")

        if submitted:
            expected_user = get_secret("APP_USERNAME") or DEFAULT_USERNAME
            expected_pass = get_secret("APP_PASSWORD") or DEFAULT_PASSWORD
            user_ok = hmac.compare_digest(username.strip(), expected_user)
            pass_ok = hmac.compare_digest(password, expected_pass)
            if user_ok and pass_ok:
                _mark_authenticated(username.strip())
                if remember:
                    try:
                        st.query_params[TOKEN_PARAM] = issue_token(username.strip())
                    except Exception:
                        pass
                st.rerun()
            else:
                st.session_state["login_attempts"] = st.session_state.get("login_attempts", 0) + 1
                st.error("账号或密码不正确，请重试。")

        st.caption("账号由服务端 Secrets 控制。配置 [auth] 可切换为 SSO 登录。")
    return False


def _oidc_configured() -> bool:
    auth = _secret_section("auth")
    return bool(auth.get("client_id") and auth.get("client_secret"))


def _allowed_emails() -> set[str]:
    raw = get_secret("ALLOWED_EMAILS") or ""
    return {item.strip().lower() for item in str(raw).replace(";", ",").split(",") if item.strip()}


def _oidc_login() -> bool:
    if getattr(st.user, "is_logged_in", False):
        email = (getattr(st.user, "email", "") or "").strip()
        allowed = _allowed_emails()
        if allowed and email.lower() not in allowed:
            st.error(f"账号 {email or '(未获取到邮箱)'} 不在允许名单内，请联系管理员。")
            try:
                st.logout()
            except Exception:
                pass
            st.stop()
        _mark_authenticated(email or "sso-user")
        return True

    mid = _render_login_shell("🚀 AI 营销与传播助手", "请使用已授权的企业/Google 账号登录")
    with mid:
        if st.button("🔐 使用 SSO 登录", type="primary"):
            st.login()
        st.caption("登录由身份提供方完成，本应用不接触你的密码。")
    return False


def require_login() -> bool:
    """已登录返回 True；否则渲染登录页（或跳转 SSO）并返回 False。"""
    if st.session_state.get("authed"):
        return True

    # 记住我 token 只在密码模式下生效：切到 SSO 后旧 token 不能绕过邮箱白名单
    if not _oidc_configured():
        if _remember_token_ok():
            return True
        return _password_login()

    return _oidc_login()


# ==================== 5. 登录闸门 ====================
# 未登录时在此中断：后面的 API Key、标题、侧边栏、三个 Tab 都不会执行
if not require_login():
    st.stop()


# ==================== 6. 业务代码 ====================
API_KEY = get_secret("DEEPSEEK_API_KEY") or ""
if not API_KEY:
    # 没配 Key 也能进界面看，只是点生成按钮时会报错，避免整页被卡死
    st.warning("提示：服务端尚未配置 `DEEPSEEK_API_KEY`，AI 生成功能暂不可用（界面可正常浏览）。")

client = OpenAI(api_key=API_KEY or "sk-not-configured", base_url="https://api.deepseek.com")

st.title("🚀 AI 营销与传播全链路助手")
st.markdown("基于 DeepSeek 大模型，一站式解决直播合规、口碑评估、短视频分镜、剪辑指导与视频诊断。")

# ==================== 侧边栏：参数配置 ====================
with st.sidebar:
    st.header("⚙️ 创作参数设置")
    st.markdown("*(仅在生成短视频相关内容时生效)*")
    platform = st.selectbox("目标平台", ["抖音", "小红书", "视频号", "B站"])
    audience = st.selectbox("目标受众", ["年轻女性", "宝妈群体", "大学生", "职场新人", "中老年群体"])
    style = st.radio("视频风格", ["真诚分享", "搞笑剧情", "干货科普", "情感共鸣"])
    st.markdown("---")
    st.info("💡 提示：我们提供从脚本策划、合规审查到后期剪辑的完整 AI 辅助工作流。")
    st.markdown("---")
    st.caption(f"👤 已登录：{current_user() or '未知用户'}")
    if st.button("🚪 退出登录"):
        # 同时清掉会话、URL 里的记住我 token、以及业务缓存
        logout()

# ==================== 主界面：三个核心选项卡 ====================
tab1, tab2, tab3 = st.tabs(["🛡️ 直播违规词审查", "😊 店铺口碑评估机", "🎬 短视频分镜与剪辑"])

# ==================== 选项卡 1：违规审查 ====================
with tab1:
    st.markdown("### 输入直播带货脚本，AI 自动排查风险")
    user_input_1 = st.text_area(
        "请输入您的直播带货脚本：",
        height=120,
        placeholder="例如：家人们，全网最低价的养生茶，喝了包治百病！"
    )
    if st.button("🚀 开启合规审查", type="primary", key="btn_tab1"):
        if not user_input_1.strip():
            st.warning("请先输入文案哦！")
        else:
            with st.spinner("AI 法务审查中..."):
                try:
                    response = client.chat.completions.create(
                        model="deepseek-flash",
                        messages=[
                            {"role": "system",
                             "content": "你是一个资深的电商直播合规审查员。找出极限词、医疗夸大、侵权风险，并给出优化后的安全文案。"},
                            {"role": "user", "content": user_input_1}
                        ]
                    )
                    st.markdown(response.choices[0].message.content)
                except Exception as e:
                    st.error(f"发生错误：{e}")

# ==================== 选项卡 2：口碑评估 ====================
with tab2:
    st.markdown("### 输入店铺信息，AI 生成情绪反馈")
    user_input_2 = st.text_input(
        "例如：济南某烧烤店，有人说肉串很香，但有人抱怨老板态度极差。",
        key="input_tab2"
    )
    if st.button("🔍 评估店铺口碑", type="primary", key="btn_tab2"):
        if not user_input_2.strip():
            st.warning("请输入店铺信息哦！")
        else:
            with st.spinner("AI 正在全网模拟分析..."):
                try:
                    response = client.chat.completions.create(
                        model="deepseek-flash",
                        messages=[
                            {"role": "system",
                             "content": "你是一个专业的店铺口碑评估专家。请判断口碑情况。如果口碑好，在回答最后加上 [SMILE]；如果存在严重差评风险，加上 [CRY]。"},
                            {"role": "user", "content": user_input_2}
                        ]
                    )
                    result = response.choices[0].message.content

                    if "[SMILE]" in result:
                        st.balloons()
                        st.markdown("<h1 style='text-align: center; font-size: 150px;'>😊</h1>", unsafe_allow_html=True)
                        st.success("口碑极佳！")
                    elif "[CRY]" in result:
                        st.markdown("<h1 style='text-align: center; font-size: 150px;'>😭</h1>", unsafe_allow_html=True)
                        st.error("口碑堪忧！")

                    st.markdown("---")
                    st.write(result.replace("[SMILE]", "").replace("[CRY]", ""))
                except Exception as e:
                    st.error(f"发生错误：{e}")

# ==================== 选项卡 3：短视频分镜与剪辑全流程 ====================
with tab3:
    st.markdown("### 输入主题，一键生成分镜脚本")
    st.info(f"当前配置：平台【{platform}】 | 受众【{audience}】 | 风格【{style}】 (可在左侧边栏修改)")

    user_input_3 = st.text_area(
        "请输入你的产品、门店或想表达的主题：",
        height=100,
        placeholder="例如：烟台红富士苹果，脆甜多汁，产地直发。",
        key="input_tab3"
    )

    if st.button("🎬 一键生成爆款分镜", type="primary", key="btn_tab3"):
        if not user_input_3.strip():
            st.warning("请先输入你的主题哦！")
        else:
            with st.spinner("AI 导演正在构思分镜和爆款文案..."):
                system_prompt = f"""
                你是一个拥有千万粉丝的短视频爆款操盘手和资深导演。
                请根据用户提供的主题，生成一份小白也能直接照拍的“短视频分镜脚本”。
                要求：
                1. 目标平台【{platform}】，目标受众【{audience}】，视频风格【{style}】。
                2. 必须包含“黄金前3秒”的留人钩子。
                3. 严格使用 Markdown 表格输出五列：| 镜号 | 时间(秒) | 画面景别与动作 | 口播文案 | 音效/BGM建议 |。
                4. 表格后给出【爆款运营建议】。
                """
                try:
                    response = client.chat.completions.create(
                        model="deepseek-flash",
                        messages=[{"role": "system", "content": system_prompt},
                                  {"role": "user", "content": f"我的主题是：{user_input_3}"}],
                        temperature=0.7
                    )
                    result_text = response.choices[0].message.content

                    st.success("🎬 导演，您的分镜脚本已生成！")
                    st.markdown("---")
                    st.markdown(result_text)

                    # 保存分镜内容，供后续模块调用
                    st.session_state['last_script'] = result_text

                    st.markdown("### 📥 导出脚本")
                    st.code(result_text, language="markdown")
                    st.caption("点击右上角的小图标即可一键复制，发给摄影师直接照着拍！")

                except Exception as e:
                    st.error(f"发生错误：{e}")

    # ------ 模块 A：剪映图文教程 ------
    st.markdown("---")
    st.markdown("### ✂️ 拍完不会剪？一键获取剪映保姆级教程")

    if st.button("🧑‍💻 生成剪映实操教程", key="btn_jianying"):
        script_content = st.session_state.get('last_script', user_input_3)

        if not script_content:
            st.warning("请先在上方输入主题并生成分镜脚本！")
        else:
            with st.spinner("AI 导师正在为你定制剪映操作流程..."):
                edit_prompt = f"""
                你是一个耐心的短视频剪辑导师。请根据以下脚本：
                【{script_content}】
                为完全不懂剪辑的新手写一份“剪映”实操教程。
                要求：
                1. 分为四阶段：素材准备、粗剪、精剪、导出。
                2. 必须细化到点哪个按钮（如：点击底部【文本】->【识别字幕】）。
                3. 当你提到关键界面时，请用【图1】或【图2】来占位。
                """
                try:
                    edit_response = client.chat.completions.create(
                        model="deepseek-flash",
                        messages=[{"role": "system", "content": edit_prompt},
                                  {"role": "user", "content": "请给我详细的剪映教程。"}],
                        temperature=0.5
                    )
                    st.success("✂️ 专属剪映教程已生成！")

                    # 这里的图片用的是网络占位图，如果加载慢不影响核心功能
                    col1, col2 = st.columns(2)
                    with col1:
                        st.image("https://images.unsplash.com/photo-1611162617474-5b21e879e113?w=400",
                                 caption="图1：剪映界面示例")
                    with col2:
                        st.image("https://images.unsplash.com/photo-1626544827763-d516dce335e2?w=400",
                                 caption="图2：添加字幕与音效示例")

                    st.markdown(edit_response.choices[0].message.content)
                except Exception as e:
                    st.error(f"教程生成失败：{e}")

    # ------ 模块 B：视频上传诊断 ------
    st.markdown("---")
    st.markdown("### 📹 视频剪辑成果检测与 AI 诊断")
    st.markdown("上传你按教程剪好的视频，AI 老师为你提供修改建议！")

    uploaded_video = st.file_uploader("请上传你的剪辑视频 (支持 mp4/mov/avi)", type=["mp4", "mov", "avi"])

    if uploaded_video is not None:
        # 播放用户上传的视频（注意：文件只在浏览器端播放，不会传给AI，0成本）
        st.video(uploaded_video)

        user_desc = st.text_area(
            "剪辑中遇到了什么问题？（描述得越详细，AI 建议越准）",
            placeholder="例如：我觉得节奏太拖沓了，不知道怎么加转场，字幕出现的时间感觉不对。"
        )

        if st.button("🩺 获取 AI 专家修改建议", type="primary", key="btn_review"):
            with st.spinner("AI 专家正在分析你的剪辑痛点..."):
                review_prompt = f"""
                你是一个资深短视频编导。用户刚刚尝试剪辑了一个视频。
                原始分镜脚本是：【{st.session_state.get('last_script', '用户未生成脚本')}】
                用户的剪辑难点描述是：【{user_desc}】

                请你根据用户的描述，给出一份专业的修改建议：
                1. 诊断痛点：指出用户描述的问题通常是因为什么导致的（如：没加关键帧、BGM没踩点）。
                2. 剪映实操建议：告诉用户在剪映里点哪几个按钮可以解决这个问题。
                3. 鼓励与优化：给出3条让视频看起来更高级的通用建议。
                """
                try:
                    review_response = client.chat.completions.create(
                        model="deepseek-flash",
                        messages=[{"role": "system", "content": review_prompt},
                                  {"role": "user", "content": "请给我修改建议。"}],
                        temperature=0.6
                    )
                    st.success("🩺 诊断报告已生成！")
                    st.markdown(review_response.choices[0].message.content)
                except Exception as e:
                    st.error(f"诊断失败：{e}")
