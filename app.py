import streamlit as st
from .waf.engine import SecureEngine

engine = SecureEngine()

st.title("SecureShield - WAF")

ip = st.text_input("IP", "192.168.1.1")
url = st.text_input("URL", "/login")
body = st.text_area("Payload", "admin' OR 1=1 --")

if st.button("Scan"):
    result = engine.process({
        "method": "POST",
        "url": url,
        "body": body
    }, ip)

    if result["blocked"]:
        st.error(f"Blocked ({result['confidence']:.0f}%)")
        for t in result["threats"]:
            st.write(t)
    else:
        st.success("Allowed")