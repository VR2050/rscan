package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemBanner3Binding implements ViewBinding {

    @NonNull
    public final ImageView image;

    @NonNull
    public final ImageView image2;

    @NonNull
    public final ImageView image3;

    @NonNull
    private final LinearLayout rootView;

    private ItemBanner3Binding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3) {
        this.rootView = linearLayout;
        this.image = imageView;
        this.image2 = imageView2;
        this.image3 = imageView3;
    }

    @NonNull
    public static ItemBanner3Binding bind(@NonNull View view) {
        int i2 = R.id.image;
        ImageView imageView = (ImageView) view.findViewById(R.id.image);
        if (imageView != null) {
            i2 = R.id.image2;
            ImageView imageView2 = (ImageView) view.findViewById(R.id.image2);
            if (imageView2 != null) {
                i2 = R.id.image3;
                ImageView imageView3 = (ImageView) view.findViewById(R.id.image3);
                if (imageView3 != null) {
                    return new ItemBanner3Binding((LinearLayout) view, imageView, imageView2, imageView3);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemBanner3Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemBanner3Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_banner3, viewGroup, false);
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
