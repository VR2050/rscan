package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemFunctionComicsBinding implements ViewBinding {

    @NonNull
    public final ShapeableImageView iconFunctionComics;

    @NonNull
    public final ImageTextView itvFunctionName;

    @NonNull
    private final LinearLayout rootView;

    private ItemFunctionComicsBinding(@NonNull LinearLayout linearLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull ImageTextView imageTextView) {
        this.rootView = linearLayout;
        this.iconFunctionComics = shapeableImageView;
        this.itvFunctionName = imageTextView;
    }

    @NonNull
    public static ItemFunctionComicsBinding bind(@NonNull View view) {
        int i2 = R.id.icon_function_comics;
        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.icon_function_comics);
        if (shapeableImageView != null) {
            i2 = R.id.itv_function_name;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_function_name);
            if (imageTextView != null) {
                return new ItemFunctionComicsBinding((LinearLayout) view, shapeableImageView, imageTextView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemFunctionComicsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemFunctionComicsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_function_comics, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
