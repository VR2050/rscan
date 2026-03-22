package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemAppsBinding implements ViewBinding {

    /* renamed from: iv */
    @NonNull
    public final ImageView f10053iv;

    @NonNull
    private final LinearLayout rootView;

    /* renamed from: tv */
    @NonNull
    public final TextView f10054tv;

    private ItemAppsBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.f10053iv = imageView;
        this.f10054tv = textView;
    }

    @NonNull
    public static ItemAppsBinding bind(@NonNull View view) {
        int i2 = R.id.f13001iv;
        ImageView imageView = (ImageView) view.findViewById(R.id.f13001iv);
        if (imageView != null) {
            i2 = R.id.f13004tv;
            TextView textView = (TextView) view.findViewById(R.id.f13004tv);
            if (textView != null) {
                return new ItemAppsBinding((LinearLayout) view, imageView, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemAppsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemAppsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_apps, viewGroup, false);
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
