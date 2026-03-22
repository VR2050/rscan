package com.lljjcoder.citywheel;

/* loaded from: classes2.dex */
public class CityConfig {
    public static final Integer NONE = -1111;
    private String cancelText;
    private String cancelTextColorStr;
    private int cancelTextSize;
    private String confirmText;
    private String confirmTextColorStr;
    private int confirmTextSize;
    private Integer customItemLayout;
    private Integer customItemTextViewId;
    private String defaultCityName;
    private String defaultDistrict;
    private String defaultProvinceName;
    private boolean drawShadows;
    private boolean isCityCyclic;
    private boolean isDistrictCyclic;
    private boolean isProvinceCyclic;
    private boolean isShowBackground;
    private String lineColor;
    private int lineHeigh;
    private String mTitle;
    public WheelType mWheelType;
    private boolean showGAT;
    private String titleBackgroundColorStr;
    private String titleTextColorStr;
    private int titleTextSize;
    private int visibleItems;

    public static class Builder {
        private Integer customItemLayout;
        private Integer customItemTextViewId;
        private int visibleItems = 5;
        private boolean isProvinceCyclic = true;
        private boolean isCityCyclic = true;
        private boolean isDistrictCyclic = true;
        private String cancelTextColorStr = "#000000";
        private String cancelText = "取消";
        private int cancelTextSize = 16;
        private String confirmTextColorStr = "#0000FF";
        private String confirmText = "确定";
        private int confirmTextSize = 16;
        private String mTitle = "选择地区";
        private String titleBackgroundColorStr = "#E9E9E9";
        private String titleTextColorStr = "#585858";
        private int titleTextSize = 18;
        private String defaultProvinceName = "浙江";
        private String defaultCityName = "杭州";
        private String defaultDistrict = "滨江区";
        private WheelType mWheelType = WheelType.PRO_CITY_DIS;
        private boolean isShowBackground = true;
        private boolean drawShadows = true;
        private String lineColor = "#C7C7C7";
        private boolean showGAT = false;
        private int lineHeigh = 3;

        public CityConfig build() {
            return new CityConfig(this);
        }

        public Builder cancelText(String str) {
            this.cancelText = str;
            return this;
        }

        public Builder cancelTextColor(String str) {
            this.cancelTextColorStr = str;
            return this;
        }

        public Builder cancelTextSize(int i2) {
            this.cancelTextSize = i2;
            return this;
        }

        public Builder city(String str) {
            this.defaultCityName = str;
            return this;
        }

        public Builder cityCyclic(boolean z) {
            this.isCityCyclic = z;
            return this;
        }

        public Builder confirTextColor(String str) {
            this.confirmTextColorStr = str;
            return this;
        }

        public Builder confirmText(String str) {
            this.confirmText = str;
            return this;
        }

        public Builder confirmTextSize(int i2) {
            this.confirmTextSize = i2;
            return this;
        }

        public Builder district(String str) {
            this.defaultDistrict = str;
            return this;
        }

        public Builder districtCyclic(boolean z) {
            this.isDistrictCyclic = z;
            return this;
        }

        public Builder drawShadows(boolean z) {
            this.drawShadows = z;
            return this;
        }

        public Builder province(String str) {
            this.defaultProvinceName = str;
            return this;
        }

        public Builder provinceCyclic(boolean z) {
            this.isProvinceCyclic = z;
            return this;
        }

        public Builder setCityWheelType(WheelType wheelType) {
            this.mWheelType = wheelType;
            return this;
        }

        public Builder setCustomItemLayout(Integer num) {
            this.customItemLayout = num;
            return this;
        }

        public Builder setCustomItemTextViewId(Integer num) {
            this.customItemTextViewId = num;
            return this;
        }

        public Builder setLineColor(String str) {
            this.lineColor = str;
            return this;
        }

        public Builder setLineHeigh(int i2) {
            this.lineHeigh = i2;
            return this;
        }

        public Builder setShowGAT(boolean z) {
            this.showGAT = z;
            return this;
        }

        public Builder showBackground(boolean z) {
            this.isShowBackground = z;
            return this;
        }

        public Builder title(String str) {
            this.mTitle = str;
            return this;
        }

        public Builder titleBackgroundColor(String str) {
            this.titleBackgroundColorStr = str;
            return this;
        }

        public Builder titleTextColor(String str) {
            this.titleTextColorStr = str;
            return this;
        }

        public Builder titleTextSize(int i2) {
            this.titleTextSize = i2;
            return this;
        }

        public Builder visibleItemsCount(int i2) {
            this.visibleItems = i2;
            return this;
        }
    }

    public enum WheelType {
        PRO,
        PRO_CITY,
        PRO_CITY_DIS
    }

    public CityConfig(Builder builder) {
        this.visibleItems = 5;
        this.isProvinceCyclic = true;
        this.isCityCyclic = true;
        this.isDistrictCyclic = true;
        this.cancelTextColorStr = "#000000";
        this.cancelText = "取消";
        this.cancelTextSize = 16;
        this.confirmTextColorStr = "#0000FF";
        this.confirmText = "确定";
        this.confirmTextSize = 16;
        this.mTitle = "选择地区";
        this.titleBackgroundColorStr = "#E9E9E9";
        this.titleTextColorStr = "#585858";
        this.titleTextSize = 18;
        this.defaultProvinceName = "浙江";
        this.defaultCityName = "杭州";
        this.defaultDistrict = "滨江区";
        this.drawShadows = true;
        this.showGAT = false;
        this.lineColor = "#C7C7C7";
        this.lineHeigh = 3;
        this.isShowBackground = true;
        this.mWheelType = WheelType.PRO_CITY_DIS;
        this.titleBackgroundColorStr = builder.titleBackgroundColorStr;
        this.mTitle = builder.mTitle;
        this.titleTextColorStr = builder.titleTextColorStr;
        this.titleTextSize = builder.titleTextSize;
        this.cancelTextColorStr = builder.cancelTextColorStr;
        this.cancelText = builder.cancelText;
        this.cancelTextSize = builder.cancelTextSize;
        this.confirmTextColorStr = builder.confirmTextColorStr;
        this.confirmText = builder.confirmText;
        this.confirmTextSize = builder.confirmTextSize;
        this.visibleItems = builder.visibleItems;
        this.isProvinceCyclic = builder.isProvinceCyclic;
        this.isDistrictCyclic = builder.isDistrictCyclic;
        this.isCityCyclic = builder.isCityCyclic;
        this.defaultDistrict = builder.defaultDistrict;
        this.defaultCityName = builder.defaultCityName;
        this.defaultProvinceName = builder.defaultProvinceName;
        this.mWheelType = builder.mWheelType;
        this.isShowBackground = builder.isShowBackground;
        this.customItemLayout = builder.customItemLayout;
        this.customItemTextViewId = builder.customItemTextViewId;
        this.drawShadows = builder.drawShadows;
        this.lineColor = builder.lineColor;
        this.lineHeigh = builder.lineHeigh;
        this.showGAT = builder.showGAT;
    }

    public String getCancelText() {
        String str = this.cancelText;
        return str == null ? "" : str;
    }

    public String getCancelTextColorStr() {
        String str = this.cancelTextColorStr;
        return str == null ? "" : str;
    }

    public int getCancelTextSize() {
        return this.cancelTextSize;
    }

    public String getConfirmText() {
        String str = this.confirmText;
        return str == null ? "" : str;
    }

    public String getConfirmTextColorStr() {
        String str = this.confirmTextColorStr;
        return str == null ? "" : str;
    }

    public int getConfirmTextSize() {
        return this.confirmTextSize;
    }

    public Integer getCustomItemLayout() {
        Integer num = this.customItemLayout;
        return num == null ? NONE : num;
    }

    public Integer getCustomItemTextViewId() {
        Integer num = this.customItemTextViewId;
        return num == null ? NONE : num;
    }

    public String getDefaultCityName() {
        String str = this.defaultCityName;
        return str == null ? "" : str;
    }

    public String getDefaultDistrict() {
        String str = this.defaultDistrict;
        return str == null ? "" : str;
    }

    public String getDefaultProvinceName() {
        String str = this.defaultProvinceName;
        return str == null ? "" : str;
    }

    public String getLineColor() {
        String str = this.lineColor;
        return str == null ? "" : str;
    }

    public int getLineHeigh() {
        return this.lineHeigh;
    }

    public String getTitle() {
        String str = this.mTitle;
        return str == null ? "" : str;
    }

    public String getTitleBackgroundColorStr() {
        String str = this.titleBackgroundColorStr;
        return str == null ? "" : str;
    }

    public String getTitleTextColorStr() {
        String str = this.titleTextColorStr;
        return str == null ? "" : str;
    }

    public int getTitleTextSize() {
        return this.titleTextSize;
    }

    public int getVisibleItems() {
        return this.visibleItems;
    }

    public WheelType getWheelType() {
        return this.mWheelType;
    }

    public boolean isCityCyclic() {
        return this.isCityCyclic;
    }

    public boolean isDistrictCyclic() {
        return this.isDistrictCyclic;
    }

    public boolean isDrawShadows() {
        return this.drawShadows;
    }

    public boolean isProvinceCyclic() {
        return this.isProvinceCyclic;
    }

    public boolean isShowBackground() {
        return this.isShowBackground;
    }

    public boolean isShowGAT() {
        return this.showGAT;
    }

    public void setCancelText(String str) {
        this.cancelText = str;
    }

    public void setCancelTextColorStr(String str) {
        this.cancelTextColorStr = str;
    }

    public void setCancelTextSize(int i2) {
        this.cancelTextSize = i2;
    }

    public void setCityCyclic(boolean z) {
        this.isCityCyclic = z;
    }

    public void setConfirmText(String str) {
        this.confirmText = str;
    }

    public void setConfirmTextColorStr(String str) {
        this.confirmTextColorStr = str;
    }

    public void setConfirmTextSize(int i2) {
        this.confirmTextSize = i2;
    }

    public void setCustomItemLayout(int i2) {
        this.customItemLayout = Integer.valueOf(i2);
    }

    public void setCustomItemTextViewId(Integer num) {
        this.customItemTextViewId = num;
    }

    public void setDefaultCityName(String str) {
        this.defaultCityName = str;
    }

    public void setDefaultDistrict(String str) {
        this.defaultDistrict = str;
    }

    public void setDefaultProvinceName(String str) {
        this.defaultProvinceName = str;
    }

    public void setDistrictCyclic(boolean z) {
        this.isDistrictCyclic = z;
    }

    public void setDrawShadows(boolean z) {
        this.drawShadows = z;
    }

    public void setLineColor(String str) {
        this.lineColor = str;
    }

    public void setLineHeigh(int i2) {
        this.lineHeigh = i2;
    }

    public void setProvinceCyclic(boolean z) {
        this.isProvinceCyclic = z;
    }

    public void setShowBackground(boolean z) {
        this.isShowBackground = z;
    }

    public void setShowGAT(boolean z) {
        this.showGAT = z;
    }

    public void setTitle(String str) {
        this.mTitle = str;
    }

    public void setTitleBackgroundColorStr(String str) {
        this.titleBackgroundColorStr = str;
    }

    public void setTitleTextColorStr(String str) {
        this.titleTextColorStr = str;
    }

    public void setTitleTextSize(int i2) {
        this.titleTextSize = i2;
    }

    public void setVisibleItems(int i2) {
        this.visibleItems = i2;
    }
}
