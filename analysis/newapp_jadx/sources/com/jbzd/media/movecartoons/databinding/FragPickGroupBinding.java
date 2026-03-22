package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.ClearEditText;

/* loaded from: classes2.dex */
public final class FragPickGroupBinding implements ViewBinding {

    @NonNull
    public final ClearEditText cetInput;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvSearch;

    @NonNull
    public final ViewPager vpContent;

    private FragPickGroupBinding(@NonNull LinearLayout linearLayout, @NonNull ClearEditText clearEditText, @NonNull LinearLayout linearLayout2, @NonNull TextView textView, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.cetInput = clearEditText;
        this.llTop = linearLayout2;
        this.tvSearch = textView;
        this.vpContent = viewPager;
    }

    @NonNull
    public static FragPickGroupBinding bind(@NonNull View view) {
        int i2 = R.id.cet_input;
        ClearEditText clearEditText = (ClearEditText) view.findViewById(R.id.cet_input);
        if (clearEditText != null) {
            i2 = R.id.ll_top;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_top);
            if (linearLayout != null) {
                i2 = R.id.tv_search;
                TextView textView = (TextView) view.findViewById(R.id.tv_search);
                if (textView != null) {
                    i2 = R.id.vp_content;
                    ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                    if (viewPager != null) {
                        return new FragPickGroupBinding((LinearLayout) view, clearEditText, linearLayout, textView, viewPager);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragPickGroupBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragPickGroupBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_pick_group, viewGroup, false);
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
