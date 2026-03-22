package com.lljjcoder.style.cityjd;

/* loaded from: classes2.dex */
public class JDCityConfig {
    private ShowType showType;

    public static class Builder {
        public ShowType showType = ShowType.PRO_CITY_DIS;

        public JDCityConfig build() {
            return new JDCityConfig(this);
        }

        public Builder setJDCityShowType(ShowType showType) {
            this.showType = showType;
            return this;
        }
    }

    public enum ShowType {
        PRO_CITY,
        PRO_CITY_DIS
    }

    public JDCityConfig(Builder builder) {
        this.showType = ShowType.PRO_CITY_DIS;
        this.showType = builder.showType;
    }

    public ShowType getShowType() {
        return this.showType;
    }

    public void setShowType(ShowType showType) {
        this.showType = showType;
    }
}
