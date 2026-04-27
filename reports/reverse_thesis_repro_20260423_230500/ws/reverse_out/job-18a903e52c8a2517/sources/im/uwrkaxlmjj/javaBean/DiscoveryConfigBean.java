package im.uwrkaxlmjj.javaBean;

import android.text.TextUtils;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
@Deprecated
public class DiscoveryConfigBean {
    private List<DataBean> Data;
    private DataBean companyData;

    public DataBean getCompanyData(String compay) {
        List<DataBean> list;
        if (this.companyData == null && !TextUtils.isEmpty(compay) && (list = this.Data) != null && !list.isEmpty()) {
            int i = 0;
            while (true) {
                if (i < this.Data.size()) {
                    DataBean d = this.Data.get(i);
                    if (d == null || !compay.equals(d.Compay)) {
                        i++;
                    } else {
                        this.companyData = this.Data.get(i);
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        return this.companyData;
    }

    public List<DataBean> getData() {
        return this.Data;
    }

    public void setData(List<DataBean> Data) {
        this.Data = Data;
    }

    public static class DataBean {
        private String CompanyName;
        private int CompanyNo;
        private String Compay;
        private List<GBean> G;
        private List<SBean> S;

        public int getCompanyNo() {
            return this.CompanyNo;
        }

        public void setCompanyNo(int CompanyNo) {
            this.CompanyNo = CompanyNo;
        }

        public String getCompay() {
            return this.Compay;
        }

        public void setCompay(String Compay) {
            this.Compay = Compay;
        }

        public String getCompanyName() {
            return this.CompanyName;
        }

        public void setCompanyName(String CompanyName) {
            this.CompanyName = CompanyName;
        }

        public List<GBean> getG() {
            List<GBean> list = this.G;
            if (list != null) {
                return list;
            }
            ArrayList arrayList = new ArrayList();
            this.G = arrayList;
            return arrayList;
        }

        public void setG(List<GBean> G) {
            this.G = G;
        }

        public List<SBean> getS() {
            List<SBean> list = this.S;
            if (list != null) {
                return list;
            }
            ArrayList arrayList = new ArrayList();
            this.S = arrayList;
            return arrayList;
        }

        public void setS(List<SBean> S) {
            this.S = S;
        }

        public static class GBean {
            private int No;
            private String Pic;
            private String Url;

            public int getNo() {
                return this.No;
            }

            public void setNo(int No) {
                this.No = No;
            }

            public String getPic() {
                return this.Pic;
            }

            public void setPic(String Pic) {
                this.Pic = Pic;
            }

            public String getUrl() {
                return this.Url;
            }

            public void setUrl(String Url) {
                this.Url = Url;
            }
        }

        public static class SBean {
            private String Logo;
            private int No;
            private String Title;
            private String Url;

            public int getNo() {
                return this.No;
            }

            public void setNo(int No) {
                this.No = No;
            }

            public String getTitle() {
                return this.Title;
            }

            public void setTitle(String Title) {
                this.Title = Title;
            }

            public String getUrl() {
                return this.Url;
            }

            public void setUrl(String Url) {
                this.Url = Url;
            }

            public String getLogo() {
                return this.Logo;
            }

            public void setLogo(String logo) {
                this.Logo = logo;
            }
        }
    }
}
