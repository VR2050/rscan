package im.uwrkaxlmjj.ui.components.banner.config;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/* JADX INFO: loaded from: classes5.dex */
public class IndicatorConfig {
    private int currentPosition;
    private int indicatorSize;
    private Margins margins;
    private int gravity = 1;
    private float indicatorSpace = BannerConfig.INDICATOR_SPACE;
    private float normalWidth = BannerConfig.INDICATOR_NORMAL_WIDTH;
    private float selectedWidth = BannerConfig.INDICATOR_SELECTED_WIDTH;
    private int normalColor = BannerConfig.INDICATOR_NORMAL_COLOR;
    private int selectedColor = BannerConfig.INDICATOR_SELECTED_COLOR;
    private float radius = BannerConfig.INDICATOR_RADIUS;
    private float height = BannerConfig.INDICATOR_HEIGHT;
    private boolean attachToBanner = true;

    @Retention(RetentionPolicy.SOURCE)
    public @interface Direction {
        public static final int CENTER = 1;
        public static final int LEFT = 0;
        public static final int RIGHT = 2;
    }

    public static class Margins {
        public int bottomMargin;
        public int leftMargin;
        public int rightMargin;
        public int topMargin;

        public Margins() {
            this(BannerConfig.INDICATOR_MARGIN);
        }

        public Margins(int marginSize) {
            this(marginSize, marginSize, marginSize, marginSize);
        }

        public Margins(int leftMargin, int topMargin, int rightMargin, int bottomMargin) {
            this.leftMargin = leftMargin;
            this.topMargin = topMargin;
            this.rightMargin = rightMargin;
            this.bottomMargin = bottomMargin;
        }
    }

    public Margins getMargins() {
        if (this.margins == null) {
            setMargins(new Margins());
        }
        return this.margins;
    }

    public IndicatorConfig setMargins(Margins margins) {
        this.margins = margins;
        return this;
    }

    public int getIndicatorSize() {
        return this.indicatorSize;
    }

    public IndicatorConfig setIndicatorSize(int indicatorSize) {
        this.indicatorSize = indicatorSize;
        return this;
    }

    public int getNormalColor() {
        return this.normalColor;
    }

    public IndicatorConfig setNormalColor(int normalColor) {
        this.normalColor = normalColor;
        return this;
    }

    public int getSelectedColor() {
        return this.selectedColor;
    }

    public IndicatorConfig setSelectedColor(int selectedColor) {
        this.selectedColor = selectedColor;
        return this;
    }

    public float getIndicatorSpace() {
        return this.indicatorSpace;
    }

    public IndicatorConfig setIndicatorSpace(float indicatorSpace) {
        this.indicatorSpace = indicatorSpace;
        return this;
    }

    public int getCurrentPosition() {
        return this.currentPosition;
    }

    public IndicatorConfig setCurrentPosition(int currentPosition) {
        this.currentPosition = currentPosition;
        return this;
    }

    public float getNormalWidth() {
        return this.normalWidth;
    }

    public IndicatorConfig setNormalWidth(float normalWidth) {
        this.normalWidth = normalWidth;
        return this;
    }

    public float getSelectedWidth() {
        return this.selectedWidth;
    }

    public IndicatorConfig setSelectedWidth(float selectedWidth) {
        this.selectedWidth = selectedWidth;
        return this;
    }

    public int getGravity() {
        return this.gravity;
    }

    public IndicatorConfig setGravity(int gravity) {
        this.gravity = gravity;
        return this;
    }

    public boolean isAttachToBanner() {
        return this.attachToBanner;
    }

    public IndicatorConfig setAttachToBanner(boolean attachToBanner) {
        this.attachToBanner = attachToBanner;
        return this;
    }

    public float getRadius() {
        return this.radius;
    }

    public IndicatorConfig setRadius(float radius) {
        this.radius = radius;
        return this;
    }

    public float getHeight() {
        return this.height;
    }

    public IndicatorConfig setHeight(float height) {
        this.height = height;
        return this;
    }
}
