import streamlit as st
import requests
import json
from streamlit_extras.badges import badge
from io import BytesIO
from xhtml2pdf import pisa

st.set_page_config(page_title="Email Header Sleuth", page_icon="🕵️", layout="wide")
st.title("🕵️ Email Header Sleuth")
st.markdown("Analyze email headers for spoofing, phishing, and more. Powered by AI and middleware magic.")

st.markdown("### 📥 Paste Your Email Header Below:")
header_input = st.text_area("Raw Email Header", height=300)

if st.button("🔍 Analyze Header"):
    if not header_input.strip():
        st.warning("Please paste an email header first.")
    else:
        with st.spinner("Analyzing header..."):
            try:
                url = "https://ip-lookup-api-middleware.onrender.com/"
                payload = {"header": header_input}
                headers = {"Content-Type": "application/json"}
                response = requests.post(url, data=json.dumps(payload), headers=headers)

                if response.status_code == 200:
                    result = response.json()
                    st.success("✅ Header Analyzed Successfully")

                    # Markdown summary
                    summary_md = f"""
📬 **Email Header Summary**
────────────────────────────
🔹 Sender Name: {result.get('sender_name')}
🔹 Real Email Address: {result.get('real_email')}
🔹 Spoofed Address: {'❌' if not result.get('spoofed') else '✅'}
🔹 IP Address: {result.get('ip')}
🔹 IP Country: {result.get('country')} ({result.get('country_code')})
🔹 IP Region: {result.get('region')}
🔹 IP City: {result.get('city')}
🔹 SPF Status: {'✅ Pass' if result.get('spf_status') == 'Pass' else '❌ Fail'}
🔹 DKIM Status: {'✅ Pass' if result.get('dkim_status') == 'Pass' else '❌ Fail'}
🔹 Domain Match: {'✅' if result.get('domain_match') else '❌'}
🔹 Known Phishing Service: {'✅' if result.get('phishing_check') else '❌ No'}
🔹 Safe Browsing Verdict: {'✅ Safe' if not result.get('google_safe') else '❌ Malicious'}
🔹 Suspicion Score: {result.get('suspicion_score')} / 15

🟩 **Overall Verdict:** {result.get('verdict')}

📝 **Notes:**
"""
                    for note in result.get("suspicion_notes", []):
                        summary_md += f"\n- ⚠️ {note}"

                    st.markdown("### 📋 Copy-Friendly Summary")
                    st.code(summary_md, language="markdown")

                    if st.button("📄 Export as PDF"):
                        def generate_pdf(content):
                            pdf_bytes = BytesIO()
                            pisa.CreatePDF(content, dest=pdf_bytes)
                            pdf_bytes.seek(0)
                            return pdf_bytes

                        summary_html = summary_md.replace("**", "<b>").replace("\n", "<br>")
                        pdf_data = generate_pdf(f"<html><body>{summary_html}</body></html>")
                        st.download_button("📥 Download PDF", data=pdf_data, file_name="header_report.pdf", mime="application/pdf")

                    # Split UI
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.markdown("## 🧪 Technical Analysis")
                        st.markdown(f"**Sender Name:** {result.get('sender_name', 'N/A')}")
                        st.markdown(f"**Real Email Address:** [{result.get('real_email', 'N/A')}](mailto:{result.get('real_email', 'N/A')})")
                        st.markdown(f"**Spoofed:** {'❌' if not result.get('spoofed') else '✅'}")
                        st.markdown(f"**IP Address:** {result.get('ip', 'N/A')}")
                        st.markdown(f"**Country:** {result.get('country', 'N/A')} ({result.get('country_code', 'N/A')})")
                        st.markdown(f"**Region:** {result.get('region', 'N/A')}")
                        st.markdown(f"**City:** {result.get('city', 'N/A')}")
                        st.markdown(f"**SPF Status:** {'✅ Pass' if result.get('spf_status') == 'Pass' else '❌ Fail'}")
                        st.markdown(f"**DKIM Status:** {'✅ Pass' if result.get('dkim_status') == 'Pass' else '❌ Fail'}")
                        st.markdown(f"**Domain Match:** {'✅ True' if result.get('domain_match') else '❌ False'}")
                        st.markdown(f"**Phishing Service Known:** {'✅' if result.get('phishing_check') else '❌'}")
                        st.markdown(f"**Safe Browsing Verdict:** {'✅ Safe' if not result.get('google_safebrowsing_flag') else '❌ Malicious'}")
                        st.markdown(f"**Suspicion Score:** `{result.get('suspicion_score')} / 15`")

                    with col2:
                        st.markdown("## 📋 Summary Report")
                        st.markdown(f"### {'🟢 Likely Legit' if result['verdict'] == 'Likely Legit' else '🟠 Possibly Spoofed' if result['verdict'] == 'Possibly Spoofed' else '🔴 Spoofed / Suspicious Header'}")
                        st.markdown("### 🧠 Why this verdict?")
                        for note in result.get("suspicion_notes", []):
                            st.markdown(f"- ⚠️ {note}")

                else:
                    st.error("❌ Failed to analyze the header.")
            except Exception as e:
                st.error(f"💥 An error occurred: {str(e)}")
