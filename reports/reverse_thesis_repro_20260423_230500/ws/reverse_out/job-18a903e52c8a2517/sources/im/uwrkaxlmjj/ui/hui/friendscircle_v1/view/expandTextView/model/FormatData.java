package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.expandTextView.model;

import com.bjz.comm.net.bean.FCEntitysResponse;
import com.bjz.comm.net.expandViewModel.LinkType;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class FormatData {
    private String formatedContent;
    private List<PositionData> positionDatas;

    public String getFormatedContent() {
        return this.formatedContent;
    }

    public void setFormatedContent(String formatedContent) {
        this.formatedContent = formatedContent;
    }

    public List<PositionData> getPositionDatas() {
        return this.positionDatas;
    }

    public void setPositionDatas(List<PositionData> positionDatas) {
        this.positionDatas = positionDatas;
    }

    public static class PositionData {
        private int end;
        private FCEntitysResponse fcEntitysResponse;
        private String selfAim;
        private String selfContent;
        private int start;
        private LinkType type;
        private String url;

        public PositionData(int start, int end, String url, LinkType type) {
            this.start = start;
            this.end = end;
            this.url = url;
            this.type = type;
        }

        public PositionData(int start, int end, String selfAim, String selfContent, LinkType type) {
            this.start = start;
            this.end = end;
            this.selfAim = selfAim;
            this.selfContent = selfContent;
            this.type = type;
        }

        public PositionData(int start, int end, String url, LinkType type, FCEntitysResponse fcEntitysResponse) {
            this.start = start;
            this.end = end;
            this.url = url;
            this.type = type;
            this.selfAim = this.selfAim;
            this.selfContent = this.selfContent;
            this.fcEntitysResponse = fcEntitysResponse;
        }

        public String getSelfAim() {
            return this.selfAim;
        }

        public void setSelfAim(String selfAim) {
            this.selfAim = selfAim;
        }

        public String getSelfContent() {
            return this.selfContent;
        }

        public void setSelfContent(String selfContent) {
            this.selfContent = selfContent;
        }

        public LinkType getType() {
            return this.type;
        }

        public void setType(LinkType type) {
            this.type = type;
        }

        public String getUrl() {
            return this.url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public int getStart() {
            return this.start;
        }

        public void setStart(int start) {
            this.start = start;
        }

        public int getEnd() {
            return this.end;
        }

        public void setEnd(int end) {
            this.end = end;
        }

        public FCEntitysResponse getFcEntitysResponse() {
            return this.fcEntitysResponse;
        }

        public void setFcEntitysResponse(FCEntitysResponse fcEntitysResponse) {
            this.fcEntitysResponse = fcEntitysResponse;
        }

        public String toString() {
            return "PositionData{start=" + this.start + ", end=" + this.end + ", url='" + this.url + "', type=" + this.type + ", selfAim='" + this.selfAim + "', selfContent='" + this.selfContent + "', fcEntitysResponse=" + this.fcEntitysResponse + '}';
        }
    }
}
