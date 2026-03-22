package com.luck.picture.lib.dialog;

import android.R;
import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.listener.OnItemClickListener;
import com.luck.picture.lib.tools.ScreenUtils;

/* loaded from: classes2.dex */
public class PhotoItemSelectedDialog extends DialogFragment implements View.OnClickListener {
    public static final int IMAGE_CAMERA = 0;
    public static final int VIDEO_CAMERA = 1;
    private OnItemClickListener onItemClickListener;
    private TextView tvPictureCancel;
    private TextView tvPicturePhoto;
    private TextView tvPictureVideo;

    private void initDialogStyle() {
        Window window;
        Dialog dialog = getDialog();
        if (dialog == null || (window = dialog.getWindow()) == null) {
            return;
        }
        window.setLayout(ScreenUtils.getScreenWidth(getContext()), -2);
        window.setGravity(80);
        window.setWindowAnimations(C3979R.style.PictureThemeDialogFragmentAnim);
    }

    public static PhotoItemSelectedDialog newInstance() {
        return new PhotoItemSelectedDialog();
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        int id = view.getId();
        OnItemClickListener onItemClickListener = this.onItemClickListener;
        if (onItemClickListener != null) {
            if (id == C3979R.id.picture_tv_photo) {
                onItemClickListener.onItemClick(view, 0);
            }
            if (id == C3979R.id.picture_tv_video) {
                this.onItemClickListener.onItemClick(view, 1);
            }
        }
        dismissAllowingStateLoss();
    }

    @Override // androidx.fragment.app.Fragment
    @Nullable
    public View onCreateView(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, @Nullable Bundle bundle) {
        if (getDialog() != null) {
            getDialog().requestWindowFeature(1);
            if (getDialog().getWindow() != null) {
                getDialog().getWindow().setBackgroundDrawableResource(R.color.transparent);
            }
        }
        return layoutInflater.inflate(C3979R.layout.picture_dialog_camera_selected, viewGroup);
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        initDialogStyle();
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(@NonNull View view, @Nullable Bundle bundle) {
        super.onViewCreated(view, bundle);
        this.tvPicturePhoto = (TextView) view.findViewById(C3979R.id.picture_tv_photo);
        this.tvPictureVideo = (TextView) view.findViewById(C3979R.id.picture_tv_video);
        this.tvPictureCancel = (TextView) view.findViewById(C3979R.id.picture_tv_cancel);
        this.tvPictureVideo.setOnClickListener(this);
        this.tvPicturePhoto.setOnClickListener(this);
        this.tvPictureCancel.setOnClickListener(this);
    }

    public void setOnItemClickListener(OnItemClickListener onItemClickListener) {
        this.onItemClickListener = onItemClickListener;
    }

    @Override // androidx.fragment.app.DialogFragment
    public void show(FragmentManager fragmentManager, String str) {
        FragmentTransaction beginTransaction = fragmentManager.beginTransaction();
        beginTransaction.add(this, str);
        beginTransaction.commitAllowingStateLoss();
    }
}
