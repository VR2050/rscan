package im.uwrkaxlmjj.translate;

import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class RespBaiDuTrasBean {
    private String error_code;
    private String from;
    private String to;
    private List<TransResult> trans_result;

    public class TransResult {
        private String dst;
        private String src;

        public TransResult() {
        }

        public String getSrc() {
            return this.src;
        }

        public void setSrc(String src) {
            this.src = src;
        }

        public String getDst() {
            return this.dst;
        }

        public void setDst(String dst) {
            this.dst = dst;
        }

        public String toString() {
            return "TransResult{src='" + this.src + "', dst='" + this.dst + "'}";
        }
    }

    public String getFrom() {
        return this.from;
    }

    public String getTo() {
        return this.to;
    }

    public void setTo(String to) {
        this.to = to;
    }

    public List<TransResult> getTrans_result() {
        return this.trans_result;
    }

    public void setTrans_result(List<TransResult> trans_result) {
        this.trans_result = trans_result;
    }

    public String getError_code() {
        return this.error_code;
    }

    public void setError_code(String error_code) {
        this.error_code = error_code;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public String toString() {
        return "RespBaiDuTrasBean{from='" + this.from + "', to='" + this.to + "', trans_result=" + this.trans_result + ", error_code='" + this.error_code + "'}";
    }
}
