package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemCategoriesModuleBinding implements ViewBinding {

    @NonNull
    public final ImageView ivImgCategories;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvNameCategories;

    @NonNull
    public final TextView tvNamePostCount;

    private ItemCategoriesModuleBinding(@NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = frameLayout;
        this.ivImgCategories = imageView;
        this.tvNameCategories = textView;
        this.tvNamePostCount = textView2;
    }

    @NonNull
    public static ItemCategoriesModuleBinding bind(@NonNull View view) {
        int i2 = R.id.iv_img_categories;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_img_categories);
        if (imageView != null) {
            i2 = R.id.tv_name_categories;
            TextView textView = (TextView) view.findViewById(R.id.tv_name_categories);
            if (textView != null) {
                i2 = R.id.tv_name_post_count;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_name_post_count);
                if (textView2 != null) {
                    return new ItemCategoriesModuleBinding((FrameLayout) view, imageView, textView, textView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemCategoriesModuleBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemCategoriesModuleBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_categories_module, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
