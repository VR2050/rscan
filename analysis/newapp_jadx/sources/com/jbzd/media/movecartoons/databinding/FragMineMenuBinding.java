package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragMineMenuBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvNickname;

    @NonNull
    public final ImageTextView itvPhone;

    @NonNull
    public final LinearLayout llBindPhone;

    @NonNull
    public final LinearLayout llCenter;

    @NonNull
    public final LinearLayout llClear;

    @NonNull
    public final LinearLayout llFind;

    @NonNull
    public final LinearLayout llGroup;

    @NonNull
    public final LinearLayout llHead;

    @NonNull
    public final LinearLayout llIDcard;

    @NonNull
    public final LinearLayout llNickname;

    @NonNull
    public final LinearLayout llService;

    @NonNull
    public final LinearLayout llVersion;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final ImageTextView tvClearSize;

    @NonNull
    public final ImageTextView tvVersion;

    private FragMineMenuBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull LinearLayout linearLayout6, @NonNull LinearLayout linearLayout7, @NonNull LinearLayout linearLayout8, @NonNull LinearLayout linearLayout9, @NonNull LinearLayout linearLayout10, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4) {
        this.rootView = relativeLayout;
        this.itvNickname = imageTextView;
        this.itvPhone = imageTextView2;
        this.llBindPhone = linearLayout;
        this.llCenter = linearLayout2;
        this.llClear = linearLayout3;
        this.llFind = linearLayout4;
        this.llGroup = linearLayout5;
        this.llHead = linearLayout6;
        this.llIDcard = linearLayout7;
        this.llNickname = linearLayout8;
        this.llService = linearLayout9;
        this.llVersion = linearLayout10;
        this.tvClearSize = imageTextView3;
        this.tvVersion = imageTextView4;
    }

    @NonNull
    public static FragMineMenuBinding bind(@NonNull View view) {
        int i2 = R.id.itv_nickname;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_nickname);
        if (imageTextView != null) {
            i2 = R.id.itv_phone;
            ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_phone);
            if (imageTextView2 != null) {
                i2 = R.id.ll_bindPhone;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_bindPhone);
                if (linearLayout != null) {
                    i2 = R.id.ll_center;
                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_center);
                    if (linearLayout2 != null) {
                        i2 = R.id.ll_clear;
                        LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_clear);
                        if (linearLayout3 != null) {
                            i2 = R.id.ll_find;
                            LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_find);
                            if (linearLayout4 != null) {
                                i2 = R.id.ll_group;
                                LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.ll_group);
                                if (linearLayout5 != null) {
                                    i2 = R.id.ll_head;
                                    LinearLayout linearLayout6 = (LinearLayout) view.findViewById(R.id.ll_head);
                                    if (linearLayout6 != null) {
                                        i2 = R.id.ll_IDcard;
                                        LinearLayout linearLayout7 = (LinearLayout) view.findViewById(R.id.ll_IDcard);
                                        if (linearLayout7 != null) {
                                            i2 = R.id.ll_nickname;
                                            LinearLayout linearLayout8 = (LinearLayout) view.findViewById(R.id.ll_nickname);
                                            if (linearLayout8 != null) {
                                                i2 = R.id.ll_service;
                                                LinearLayout linearLayout9 = (LinearLayout) view.findViewById(R.id.ll_service);
                                                if (linearLayout9 != null) {
                                                    i2 = R.id.ll_version;
                                                    LinearLayout linearLayout10 = (LinearLayout) view.findViewById(R.id.ll_version);
                                                    if (linearLayout10 != null) {
                                                        i2 = R.id.tv_clearSize;
                                                        ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.tv_clearSize);
                                                        if (imageTextView3 != null) {
                                                            i2 = R.id.tv_version;
                                                            ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.tv_version);
                                                            if (imageTextView4 != null) {
                                                                return new FragMineMenuBinding((RelativeLayout) view, imageTextView, imageTextView2, linearLayout, linearLayout2, linearLayout3, linearLayout4, linearLayout5, linearLayout6, linearLayout7, linearLayout8, linearLayout9, linearLayout10, imageTextView3, imageTextView4);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragMineMenuBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragMineMenuBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_mine_menu, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
