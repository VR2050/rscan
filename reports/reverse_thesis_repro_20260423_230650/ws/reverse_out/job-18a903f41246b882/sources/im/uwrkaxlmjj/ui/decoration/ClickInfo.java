package im.uwrkaxlmjj.ui.decoration;

import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class ClickInfo {
    public int mBottom;
    public List<DetailInfo> mDetailInfoList;
    public int mGroupId = -1;

    public ClickInfo(int bottom) {
        this.mBottom = bottom;
    }

    public ClickInfo(int bottom, List<DetailInfo> detailInfoList) {
        this.mBottom = bottom;
        this.mDetailInfoList = detailInfoList;
    }

    public static class DetailInfo {
        public int bottom;
        public int id;
        public int left;
        public int right;
        public int top;

        public DetailInfo(int id, int left, int right, int top, int bottom) {
            this.id = id;
            this.left = left;
            this.right = right;
            this.top = top;
            this.bottom = bottom;
        }
    }
}
