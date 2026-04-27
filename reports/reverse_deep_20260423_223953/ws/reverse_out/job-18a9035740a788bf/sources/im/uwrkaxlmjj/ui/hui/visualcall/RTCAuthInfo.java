package im.uwrkaxlmjj.ui.hui.visualcall;

import java.io.Serializable;

/* JADX INFO: loaded from: classes5.dex */
public class RTCAuthInfo implements Serializable {
    public int code;
    public RTCAuthInfo_Data data;
    public int server;

    public static class RTCAuthInfo_Data implements Serializable {
        public String appid;
        public String[] gslb;
        public String key;
        public String nonce;
        public long timestamp;
        public String token;
        public RTCAuthInfo_Data_Turn turn;
        public String userid;

        public String getAppid() {
            return this.appid;
        }

        public void setAppid(String appid) {
            this.appid = appid;
        }

        public String getUserid() {
            return this.userid;
        }

        public void setUserid(String userid) {
            this.userid = userid;
        }

        public String getNonce() {
            return this.nonce;
        }

        public void setNonce(String nonce) {
            this.nonce = nonce;
        }

        public long getTimestamp() {
            return this.timestamp;
        }

        public void setTimestamp(long timestamp) {
            this.timestamp = timestamp;
        }

        public String getToken() {
            return this.token;
        }

        public void setToken(String token) {
            this.token = token;
        }

        public RTCAuthInfo_Data_Turn getTurn() {
            return this.turn;
        }

        public void setTurn(RTCAuthInfo_Data_Turn turn) {
            this.turn = turn;
        }

        public String[] getGslb() {
            return this.gslb;
        }

        public void setGslb(String[] gslb) {
            this.gslb = gslb;
        }

        public String getKey() {
            return this.key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public static class RTCAuthInfo_Data_Turn implements Serializable {
            public String password;
            public String username;

            public String getUsername() {
                return this.username;
            }

            public void setUsername(String username) {
                this.username = username;
            }

            public String getPassword() {
                return this.password;
            }

            public void setPassword(String password) {
                this.password = password;
            }
        }
    }

    public int getCode() {
        return this.code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public RTCAuthInfo_Data getData() {
        return this.data;
    }

    public void setData(RTCAuthInfo_Data data) {
        this.data = data;
    }

    public int getServer() {
        return this.server;
    }

    public void setServer(int server) {
        this.server = server;
    }
}
