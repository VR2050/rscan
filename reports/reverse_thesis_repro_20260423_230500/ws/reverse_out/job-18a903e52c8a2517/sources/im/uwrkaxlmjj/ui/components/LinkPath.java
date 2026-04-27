package im.uwrkaxlmjj.ui.components;

import android.graphics.Path;
import android.graphics.RectF;
import android.os.Build;
import android.text.StaticLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class LinkPath extends Path {
    private int baselineShift;
    private StaticLayout currentLayout;
    private int currentLine;
    private float heightOffset;
    private int lineHeight;
    private RectF rect;
    private boolean useRoundRect;
    private float lastTop = -1.0f;
    private boolean allowReset = true;

    public LinkPath() {
    }

    public LinkPath(boolean roundRect) {
        this.useRoundRect = roundRect;
    }

    public void setCurrentLayout(StaticLayout layout, int start, float yOffset) {
        int lineCount;
        this.currentLayout = layout;
        this.currentLine = layout.getLineForOffset(start);
        this.lastTop = -1.0f;
        this.heightOffset = yOffset;
        if (Build.VERSION.SDK_INT >= 28 && (lineCount = layout.getLineCount()) > 0) {
            this.lineHeight = layout.getLineBottom(lineCount - 1) - layout.getLineTop(lineCount - 1);
        }
    }

    public void setAllowReset(boolean value) {
        this.allowReset = value;
    }

    public void setUseRoundRect(boolean value) {
        this.useRoundRect = value;
    }

    public boolean isUsingRoundRect() {
        return this.useRoundRect;
    }

    public void setBaselineShift(int value) {
        this.baselineShift = value;
    }

    @Override // android.graphics.Path
    public void addRect(float left, float top, float right, float bottom, Path.Direction dir) {
        float y2;
        float y;
        float y22;
        float f = this.heightOffset;
        float top2 = top + f;
        float bottom2 = bottom + f;
        float f2 = this.lastTop;
        if (f2 == -1.0f) {
            this.lastTop = top2;
        } else if (f2 != top2) {
            this.lastTop = top2;
            this.currentLine++;
        }
        float lineRight = this.currentLayout.getLineRight(this.currentLine);
        float lineLeft = this.currentLayout.getLineLeft(this.currentLine);
        if (left < lineRight) {
            if (left <= lineLeft && right <= lineLeft) {
                return;
            }
            if (right > lineRight) {
                right = lineRight;
            }
            if (left < lineLeft) {
                left = lineLeft;
            }
            if (Build.VERSION.SDK_INT >= 28) {
                y2 = bottom2;
                if (bottom2 - top2 > this.lineHeight) {
                    y2 = this.heightOffset + (bottom2 != ((float) this.currentLayout.getHeight()) ? this.currentLayout.getLineBottom(this.currentLine) - this.currentLayout.getSpacingAdd() : 0.0f);
                }
            } else {
                y2 = bottom2 - (bottom2 != ((float) this.currentLayout.getHeight()) ? this.currentLayout.getSpacingAdd() : 0.0f);
            }
            int i = this.baselineShift;
            if (i < 0) {
                y = top2;
                y22 = y2 + i;
            } else if (i > 0) {
                float y3 = top2 + i;
                y = y3;
                y22 = y2;
            } else {
                y = top2;
                y22 = y2;
            }
            if (this.useRoundRect) {
                if (this.rect == null) {
                    this.rect = new RectF();
                }
                this.rect.set(left - AndroidUtilities.dp(4.0f), y, AndroidUtilities.dp(4.0f) + right, y22);
                super.addRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), dir);
                return;
            }
            super.addRect(left, y, right, y22, dir);
        }
    }

    @Override // android.graphics.Path
    public void reset() {
        if (!this.allowReset) {
            return;
        }
        super.reset();
    }
}
