import streamlit as st
from pipeline import ISROVulnerabilityPipeline

# Cache the model loading so it only happens once when the app starts
@st.cache_resource
def load_pipeline():
    with st.spinner("Loading ISRO Two-Stage Pipeline Models into VRAM..."):
        return ISROVulnerabilityPipeline()

def main():
    st.set_page_config(page_title="ISRO Vulnerability Scanner", page_icon="🛡️", layout="wide")
    
    st.title("VULNERA")
    st.markdown("Upload a code file or manually paste a code snippet to evaluate it against the 2-Stage Neural Pipeline.")

    try:
        pipeline = load_pipeline()
    except Exception as e:
        st.error(f"Failed to load models. Ensure stage1_unixcoder.pth and stage2_unixcoder.pth exist. Error: {e}")
        st.stop()

    # Create tabs for the two requested input methods
    tab1, tab2 = st.tabs(["📝 Paste Code", "📁 Upload File"])
    
    code_to_analyze = None

    with tab1:
        st.markdown("### Manual Code Entry")
        pasted_code = st.text_area("Paste your source code here:", height=300)
        if st.button("Analyze Pasted Code", type="primary", use_container_width=True):
            if pasted_code.strip():
                code_to_analyze = pasted_code
            else:
                st.warning("Please paste some code first.")
                
    with tab2:
        st.markdown("### File Upload")
        uploaded_file = st.file_uploader("Choose a source code file (.c, .cpp, .java, .py, etc.)")
        if uploaded_file is not None:
            # Read and decode the uploaded file
            file_contents = uploaded_file.getvalue().decode("utf-8", errors="ignore")
            st.code(file_contents, language='java') 
            if st.button("Analyze Uploaded File", type="primary", use_container_width=True):
                code_to_analyze = file_contents

    # Analysis Execution and Result Display
    if code_to_analyze:
        st.markdown("---")
        st.subheader("📊 Analysis Results")
        
        with st.spinner("Analyzing code..."):
            results = pipeline.analyze_code(code_to_analyze)
            
        # Display the visual metric cards
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Stage 1: Vulnerability Detection")
            if results['status'] == "Safe":
                st.success(f"**Status:** {results['status']}")
            else:
                st.error(f"**Status:** {results['status']}")
                
            st.info(f"**Vulnerability Confidence:** {results['vulnerability_confidence']}")
            
        with col2:
            st.markdown("#### Stage 2: CWE Classification")
            if results.get('detected_cwes'):
                for cwe in results['detected_cwes']:
                    confidence = results['cwe_confidences'].get(cwe, 'N/A')
                    st.warning(f"**Detected {cwe}** (Confidence: {confidence})")
            else:
                st.success("**Detected CWE:** None (Code is Safe)")
                
        # Show the raw JSON terminal output exactly as requested
        st.markdown("#### Raw Pipeline Output")
        st.json(results)

if __name__ == "__main__":
    main()