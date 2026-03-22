package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.ClearEditText;

/* loaded from: classes2.dex */
public final class DialogBookingSuccessBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btnBookingsuccessSure;

    @NonNull
    public final ClearEditText etContact;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final View view2;

    private DialogBookingSuccessBinding(@NonNull LinearLayout linearLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull ClearEditText clearEditText, @NonNull ImageView imageView, @NonNull View view) {
        this.rootView = linearLayout;
        this.btnBookingsuccessSure = gradientRoundCornerButton;
        this.etContact = clearEditText;
        this.ivClose = imageView;
        this.view2 = view;
    }

    @NonNull
    public static DialogBookingSuccessBinding bind(@NonNull View view) {
        int i2 = R.id.btn_bookingsuccess_sure;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btn_bookingsuccess_sure);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.et_contact;
            ClearEditText clearEditText = (ClearEditText) view.findViewById(R.id.et_contact);
            if (clearEditText != null) {
                i2 = R.id.iv_close;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
                if (imageView != null) {
                    i2 = R.id.view2;
                    View findViewById = view.findViewById(R.id.view2);
                    if (findViewById != null) {
                        return new DialogBookingSuccessBinding((LinearLayout) view, gradientRoundCornerButton, clearEditText, imageView, findViewById);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogBookingSuccessBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogBookingSuccessBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_booking_success, viewGroup, false);
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
