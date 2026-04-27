package com.tablayout.transformer;

import android.util.Log;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import com.tablayout.SlidingScaleTabLayout;

/* JADX INFO: loaded from: classes2.dex */
public class TabScaleTransformer implements ITabScaleTransformer {
    protected boolean openDmg;
    protected SlidingScaleTabLayout slidingScaleTabLayout;
    private float textSelectSize;
    private float textUnSelectSize;

    public TabScaleTransformer(SlidingScaleTabLayout slidingScaleTabLayout, float textSelectSize, float textUnSelectSize, boolean openDmg) {
        this.slidingScaleTabLayout = slidingScaleTabLayout;
        this.textSelectSize = textSelectSize;
        this.textUnSelectSize = textUnSelectSize;
        this.openDmg = openDmg;
    }

    @Override // com.tablayout.transformer.ITabScaleTransformer
    public void setNormalWidth(int position, int width, boolean isSelect) {
    }

    @Override // com.tablayout.transformer.ITabScaleTransformer
    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
        Log.i("TabScaleTransformer", "position:" + position);
        if (this.textSelectSize == this.textUnSelectSize) {
            return;
        }
        if (this.openDmg) {
            for (int i = 0; i < this.slidingScaleTabLayout.getTabCount(); i++) {
                if (i != position && i != position + 1) {
                    changTabDmgWidth(i, 0.0f);
                }
            }
            changeDmgSize(position, positionOffset);
            return;
        }
        for (int i2 = 0; i2 < this.slidingScaleTabLayout.getTabCount(); i2++) {
            if (i2 != position && i2 != position + 1) {
                updateTextSize(i2, 1.0f);
            }
        }
        changeTextSize(position, positionOffset);
    }

    private void changeTextSize(int position, float positionOffset) {
        updateTextSize(position, positionOffset);
        if (position + 1 < this.slidingScaleTabLayout.getTabCount()) {
            updateTextSize(position + 1, 1.0f - positionOffset);
        }
    }

    private void updateTextSize(int position, final float positionOffset) {
        final TextView currentTab = this.slidingScaleTabLayout.getTitle(position);
        currentTab.post(new Runnable() { // from class: com.tablayout.transformer.TabScaleTransformer.1
            @Override // java.lang.Runnable
            public void run() {
                int textSize = (int) (TabScaleTransformer.this.textSelectSize - Math.abs((TabScaleTransformer.this.textSelectSize - TabScaleTransformer.this.textUnSelectSize) * positionOffset));
                if (currentTab.getTextSize() != textSize) {
                    currentTab.setTextSize(0, textSize);
                    currentTab.requestLayout();
                }
            }
        });
    }

    private void changeDmgSize(final int position, final float positionOffset) {
        this.slidingScaleTabLayout.post(new Runnable() { // from class: com.tablayout.transformer.TabScaleTransformer.2
            @Override // java.lang.Runnable
            public void run() {
                float scale = 1.0f - positionOffset;
                TabScaleTransformer.this.changTabDmgWidth(position, scale);
                if (position + 1 < TabScaleTransformer.this.slidingScaleTabLayout.getTabCount()) {
                    TabScaleTransformer.this.changTabDmgWidth(position + 1, positionOffset);
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void changTabDmgWidth(int position, float scale) {
        ImageView currentTabDmg = this.slidingScaleTabLayout.getDmgView(position);
        if (currentTabDmg == null || currentTabDmg.getDrawable() == null) {
            return;
        }
        ViewGroup.LayoutParams params = currentTabDmg.getLayoutParams();
        int width = (int) (currentTabDmg.getMinimumWidth() + ((currentTabDmg.getMaxWidth() - currentTabDmg.getMinimumWidth()) * scale));
        if (params.width != width) {
            params.width = width;
            currentTabDmg.setLayoutParams(params);
        }
    }
}
