package com.tablayout.transformer;

import android.view.View;
import androidx.viewpager.widget.ViewPager;
import androidx.viewpager2.widget.ViewPager2;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class ExtendTransformer implements ViewPager.PageTransformer, ViewPager2.PageTransformer {
    private ArrayList<IViewPagerTransformer> transformers = new ArrayList<>();

    public void addViewPagerTransformer(IViewPagerTransformer transformer) {
        if (!this.transformers.contains(transformer)) {
            this.transformers.add(transformer);
        }
    }

    public void removeViewPagerTransformer(IViewPagerTransformer transformer) {
        this.transformers.remove(transformer);
    }

    public List<IViewPagerTransformer> getTransformers() {
        return this.transformers;
    }

    public void setTransformers(List<IViewPagerTransformer> transformers) {
        this.transformers.addAll(transformers);
    }

    @Override // androidx.viewpager.widget.ViewPager.PageTransformer, androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(View view, float position) {
        ArrayList<IViewPagerTransformer> arrayList = this.transformers;
        if (arrayList != null && arrayList.size() > 0) {
            for (IViewPagerTransformer transformer : this.transformers) {
                transformer.transformPage(view, position);
            }
        }
    }
}
