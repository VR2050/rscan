package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.CommonShapeButton;

/* loaded from: classes2.dex */
public final class DialogPortraitUploadTipsBinding implements ViewBinding {

    @NonNull
    public final CommonShapeButton btnCancel;

    @NonNull
    public final CommonShapeButton btnOpenVip;

    @NonNull
    public final LinearLayout llCard;

    @NonNull
    private final FrameLayout rootView;

    private DialogPortraitUploadTipsBinding(@NonNull FrameLayout frameLayout, @NonNull CommonShapeButton commonShapeButton, @NonNull CommonShapeButton commonShapeButton2, @NonNull LinearLayout linearLayout) {
        this.rootView = frameLayout;
        this.btnCancel = commonShapeButton;
        this.btnOpenVip = commonShapeButton2;
        this.llCard = linearLayout;
    }

    @NonNull
    public static DialogPortraitUploadTipsBinding bind(@NonNull View view) {
        int i2 = R.id.btn_cancel;
        CommonShapeButton commonShapeButton = (CommonShapeButton) view.findViewById(R.id.btn_cancel);
        if (commonShapeButton != null) {
            i2 = R.id.btn_openVip;
            CommonShapeButton commonShapeButton2 = (CommonShapeButton) view.findViewById(R.id.btn_openVip);
            if (commonShapeButton2 != null) {
                i2 = R.id.ll_card;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_card);
                if (linearLayout != null) {
                    return new DialogPortraitUploadTipsBinding((FrameLayout) view, commonShapeButton, commonShapeButton2, linearLayout);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogPortraitUploadTipsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogPortraitUploadTipsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_portrait_upload_tips, viewGroup, false);
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
