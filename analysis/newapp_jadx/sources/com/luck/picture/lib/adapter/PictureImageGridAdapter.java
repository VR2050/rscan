package com.luck.picture.lib.adapter;

import android.content.Context;
import android.graphics.PorterDuff;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.adapter.PictureImageGridAdapter;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.dialog.PictureCustomDialog;
import com.luck.picture.lib.engine.ImageEngine;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnPhotoSelectChangedListener;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import com.luck.picture.lib.tools.AttrsUtils;
import com.luck.picture.lib.tools.DateUtils;
import com.luck.picture.lib.tools.MediaUtils;
import com.luck.picture.lib.tools.StringUtils;
import com.luck.picture.lib.tools.ToastUtils;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public class PictureImageGridAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {
    private PictureSelectionConfig config;
    private Context context;
    private OnPhotoSelectChangedListener imageSelectChangedListener;
    private boolean showCamera;
    private List<LocalMedia> data = new ArrayList();
    private List<LocalMedia> selectData = new ArrayList();

    public class CameraViewHolder extends RecyclerView.ViewHolder {
        public TextView tvCamera;

        public CameraViewHolder(View view) {
            super(view);
            TextView textView = (TextView) view.findViewById(C3979R.id.tvCamera);
            this.tvCamera = textView;
            PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle == null) {
                textView.setText(PictureImageGridAdapter.this.config.chooseMode == PictureMimeType.ofAudio() ? PictureImageGridAdapter.this.context.getString(C3979R.string.picture_tape) : PictureImageGridAdapter.this.context.getString(C3979R.string.picture_take_picture));
                return;
            }
            int i2 = pictureSelectorUIStyle.picture_adapter_item_camera_backgroundColor;
            if (i2 != 0) {
                view.setBackgroundColor(i2);
            }
            int i3 = PictureSelectionConfig.uiStyle.picture_adapter_item_camera_textSize;
            if (i3 != 0) {
                this.tvCamera.setTextSize(i3);
            }
            int i4 = PictureSelectionConfig.uiStyle.picture_adapter_item_camera_textColor;
            if (i4 != 0) {
                this.tvCamera.setTextColor(i4);
            }
            if (TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_adapter_item_camera_text)) {
                this.tvCamera.setText(PictureImageGridAdapter.this.config.chooseMode == PictureMimeType.ofAudio() ? PictureImageGridAdapter.this.context.getString(C3979R.string.picture_tape) : PictureImageGridAdapter.this.context.getString(C3979R.string.picture_take_picture));
            } else {
                this.tvCamera.setText(PictureSelectionConfig.uiStyle.picture_adapter_item_camera_text);
            }
            int i5 = PictureSelectionConfig.uiStyle.picture_adapter_item_camera_textTopDrawable;
            if (i5 != 0) {
                this.tvCamera.setCompoundDrawablesWithIntrinsicBounds(0, i5, 0, 0);
            }
        }
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public View btnCheck;
        public View contentView;
        public ImageView ivPicture;
        public TextView tvCheck;
        public TextView tvDuration;
        public TextView tvIsGif;
        public TextView tvLongChart;

        public ViewHolder(View view) {
            super(view);
            this.contentView = view;
            this.ivPicture = (ImageView) view.findViewById(C3979R.id.ivPicture);
            this.tvCheck = (TextView) view.findViewById(C3979R.id.tvCheck);
            this.btnCheck = view.findViewById(C3979R.id.btnCheck);
            this.tvDuration = (TextView) view.findViewById(C3979R.id.tv_duration);
            this.tvIsGif = (TextView) view.findViewById(C3979R.id.tv_isGif);
            this.tvLongChart = (TextView) view.findViewById(C3979R.id.tv_long_chart);
            PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle == null) {
                PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
                if (pictureParameterStyle == null) {
                    this.tvCheck.setBackground(AttrsUtils.getTypeValueDrawable(view.getContext(), C3979R.attr.picture_checked_style, C3979R.drawable.picture_checkbox_selector));
                    return;
                } else {
                    int i2 = pictureParameterStyle.pictureCheckedStyle;
                    if (i2 != 0) {
                        this.tvCheck.setBackgroundResource(i2);
                        return;
                    }
                    return;
                }
            }
            int i3 = pictureSelectorUIStyle.picture_check_style;
            if (i3 != 0) {
                this.tvCheck.setBackgroundResource(i3);
            }
            int i4 = PictureSelectionConfig.uiStyle.picture_check_textSize;
            if (i4 != 0) {
                this.tvCheck.setTextSize(i4);
            }
            int i5 = PictureSelectionConfig.uiStyle.picture_check_textColor;
            if (i5 != 0) {
                this.tvCheck.setTextColor(i5);
            }
            int i6 = PictureSelectionConfig.uiStyle.picture_adapter_item_textSize;
            if (i6 > 0) {
                this.tvDuration.setTextSize(i6);
            }
            int i7 = PictureSelectionConfig.uiStyle.picture_adapter_item_textColor;
            if (i7 != 0) {
                this.tvDuration.setTextColor(i7);
            }
            if (!TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_adapter_item_tag_text)) {
                this.tvIsGif.setText(PictureSelectionConfig.uiStyle.picture_adapter_item_tag_text);
            }
            if (PictureSelectionConfig.uiStyle.picture_adapter_item_gif_tag_show) {
                this.tvIsGif.setVisibility(0);
            } else {
                this.tvIsGif.setVisibility(8);
            }
            int i8 = PictureSelectionConfig.uiStyle.picture_adapter_item_gif_tag_background;
            if (i8 != 0) {
                this.tvIsGif.setBackgroundResource(i8);
            }
            int i9 = PictureSelectionConfig.uiStyle.picture_adapter_item_gif_tag_textColor;
            if (i9 != 0) {
                this.tvIsGif.setTextColor(i9);
            }
            int i10 = PictureSelectionConfig.uiStyle.picture_adapter_item_gif_tag_textSize;
            if (i10 != 0) {
                this.tvIsGif.setTextSize(i10);
            }
        }
    }

    public PictureImageGridAdapter(Context context, PictureSelectionConfig pictureSelectionConfig) {
        this.context = context;
        this.config = pictureSelectionConfig;
        this.showCamera = pictureSelectionConfig.isCamera;
    }

    /* JADX WARN: Code restructure failed: missing block: B:71:0x0332, code lost:
    
        if (getSelectedSize() == (r11.config.maxSelectNum - 1)) goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x038c, code lost:
    
        r2 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x0344, code lost:
    
        if (getSelectedSize() == 0) goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x036f, code lost:
    
        if (getSelectedSize() == (r11.config.maxVideoSelectNum - 1)) goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x038a, code lost:
    
        if (getSelectedSize() == (r11.config.maxSelectNum - 1)) goto L175;
     */
    @android.annotation.SuppressLint({"StringFormatMatches"})
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void changeCheckboxState(com.luck.picture.lib.adapter.PictureImageGridAdapter.ViewHolder r12, com.luck.picture.lib.entity.LocalMedia r13) {
        /*
            Method dump skipped, instructions count: 937
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.adapter.PictureImageGridAdapter.changeCheckboxState(com.luck.picture.lib.adapter.PictureImageGridAdapter$ViewHolder, com.luck.picture.lib.entity.LocalMedia):void");
    }

    private void dispatchHandleMask(ViewHolder viewHolder, LocalMedia localMedia) {
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.isWithVideoImage && pictureSelectionConfig.maxVideoSelectNum > 0) {
            if (getSelectedSize() < this.config.maxSelectNum) {
                localMedia.setMaxSelectEnabledMask(false);
                return;
            }
            boolean isSelected = viewHolder.tvCheck.isSelected();
            viewHolder.ivPicture.setColorFilter(ContextCompat.getColor(this.context, isSelected ? C3979R.color.picture_color_80 : C3979R.color.picture_color_half_white), PorterDuff.Mode.SRC_ATOP);
            localMedia.setMaxSelectEnabledMask(!isSelected);
            return;
        }
        LocalMedia localMedia2 = this.selectData.size() > 0 ? this.selectData.get(0) : null;
        if (localMedia2 != null) {
            boolean isSelected2 = viewHolder.tvCheck.isSelected();
            if (this.config.chooseMode != PictureMimeType.ofAll()) {
                if (this.config.chooseMode != PictureMimeType.ofVideo() || this.config.maxVideoSelectNum <= 0) {
                    if (!isSelected2 && getSelectedSize() == this.config.maxSelectNum) {
                        viewHolder.ivPicture.setColorFilter(ContextCompat.getColor(this.context, C3979R.color.picture_color_half_white), PorterDuff.Mode.SRC_ATOP);
                    }
                    localMedia.setMaxSelectEnabledMask(!isSelected2 && getSelectedSize() == this.config.maxSelectNum);
                    return;
                }
                if (!isSelected2 && getSelectedSize() == this.config.maxVideoSelectNum) {
                    viewHolder.ivPicture.setColorFilter(ContextCompat.getColor(this.context, C3979R.color.picture_color_half_white), PorterDuff.Mode.SRC_ATOP);
                }
                localMedia.setMaxSelectEnabledMask(!isSelected2 && getSelectedSize() == this.config.maxVideoSelectNum);
                return;
            }
            if (PictureMimeType.isHasImage(localMedia2.getMimeType())) {
                if (!isSelected2 && !PictureMimeType.isHasImage(localMedia.getMimeType())) {
                    viewHolder.ivPicture.setColorFilter(ContextCompat.getColor(this.context, PictureMimeType.isHasVideo(localMedia.getMimeType()) ? C3979R.color.picture_color_half_white : C3979R.color.picture_color_20), PorterDuff.Mode.SRC_ATOP);
                }
                localMedia.setMaxSelectEnabledMask(PictureMimeType.isHasVideo(localMedia.getMimeType()));
                return;
            }
            if (PictureMimeType.isHasVideo(localMedia2.getMimeType())) {
                if (!isSelected2 && !PictureMimeType.isHasVideo(localMedia.getMimeType())) {
                    viewHolder.ivPicture.setColorFilter(ContextCompat.getColor(this.context, PictureMimeType.isHasImage(localMedia.getMimeType()) ? C3979R.color.picture_color_half_white : C3979R.color.picture_color_20), PorterDuff.Mode.SRC_ATOP);
                }
                localMedia.setMaxSelectEnabledMask(PictureMimeType.isHasImage(localMedia.getMimeType()));
            }
        }
    }

    private void notifyCheckChanged(ViewHolder viewHolder, LocalMedia localMedia) {
        viewHolder.tvCheck.setText("");
        int size = this.selectData.size();
        for (int i2 = 0; i2 < size; i2++) {
            LocalMedia localMedia2 = this.selectData.get(i2);
            if (localMedia2.getPath().equals(localMedia.getPath()) || localMedia2.getId() == localMedia.getId()) {
                localMedia.setNum(localMedia2.getNum());
                localMedia2.setPosition(localMedia.getPosition());
                viewHolder.tvCheck.setText(String.valueOf(localMedia.getNum()));
            }
        }
    }

    private void showPromptDialog(String str) {
        final PictureCustomDialog pictureCustomDialog = new PictureCustomDialog(this.context, C3979R.layout.picture_prompt_dialog);
        TextView textView = (TextView) pictureCustomDialog.findViewById(C3979R.id.btnOk);
        ((TextView) pictureCustomDialog.findViewById(C3979R.id.tv_content)).setText(str);
        textView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.h0.d
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureCustomDialog.this.dismiss();
            }
        });
        pictureCustomDialog.show();
    }

    private void singleRadioMediaImage() {
        List<LocalMedia> list = this.selectData;
        if (list == null || list.size() <= 0) {
            return;
        }
        notifyItemChanged(this.selectData.get(0).position);
        this.selectData.clear();
    }

    private void subSelectPosition() {
        if (this.config.checkNumMode) {
            int size = this.selectData.size();
            int i2 = 0;
            while (i2 < size) {
                LocalMedia localMedia = this.selectData.get(i2);
                i2++;
                localMedia.setNum(i2);
                notifyItemChanged(localMedia.position);
            }
        }
    }

    /* renamed from: a */
    public /* synthetic */ void m4535a(View view) {
        OnPhotoSelectChangedListener onPhotoSelectChangedListener = this.imageSelectChangedListener;
        if (onPhotoSelectChangedListener != null) {
            onPhotoSelectChangedListener.onTakePhoto();
        }
    }

    /* renamed from: b */
    public /* synthetic */ void m4536b(LocalMedia localMedia, ViewHolder viewHolder, String str, View view) {
        String msg;
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.isMaxSelectEnabledMask) {
            if (pictureSelectionConfig.isWithVideoImage) {
                int selectedSize = getSelectedSize();
                boolean z = false;
                int i2 = 0;
                for (int i3 = 0; i3 < selectedSize; i3++) {
                    if (PictureMimeType.isHasVideo(this.selectData.get(i3).getMimeType())) {
                        i2++;
                    }
                }
                if (PictureMimeType.isHasVideo(localMedia.getMimeType())) {
                    if (!viewHolder.tvCheck.isSelected() && i2 >= this.config.maxVideoSelectNum) {
                        z = true;
                    }
                    msg = StringUtils.getMsg(this.context, localMedia.getMimeType(), this.config.maxVideoSelectNum);
                } else {
                    if (!viewHolder.tvCheck.isSelected() && selectedSize >= this.config.maxSelectNum) {
                        z = true;
                    }
                    msg = StringUtils.getMsg(this.context, localMedia.getMimeType(), this.config.maxSelectNum);
                }
                if (z) {
                    showPromptDialog(msg);
                    return;
                }
            } else if (!viewHolder.tvCheck.isSelected() && getSelectedSize() >= this.config.maxSelectNum) {
                showPromptDialog(StringUtils.getMsg(this.context, localMedia.getMimeType(), this.config.maxSelectNum));
                return;
            }
        }
        String realPath = localMedia.getRealPath();
        if (TextUtils.isEmpty(realPath) || new File(realPath).exists()) {
            Context context = this.context;
            PictureSelectionConfig pictureSelectionConfig2 = this.config;
            MediaUtils.setOrientationAsynchronous(context, localMedia, pictureSelectionConfig2.isAndroidQChangeWH, pictureSelectionConfig2.isAndroidQChangeVideoWH, null);
            changeCheckboxState(viewHolder, localMedia);
        } else {
            Context context2 = this.context;
            ToastUtils.m4555s(context2, PictureMimeType.m4554s(context2, str));
        }
    }

    public void bindData(List<LocalMedia> list) {
        if (list == null) {
            list = new ArrayList<>();
        }
        this.data = list;
        notifyDataSetChanged();
    }

    public void bindSelectData(List<LocalMedia> list) {
        ArrayList arrayList = new ArrayList();
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            arrayList.add(list.get(i2));
        }
        this.selectData = arrayList;
        if (this.config.isSingleDirectReturn) {
            return;
        }
        subSelectPosition();
        OnPhotoSelectChangedListener onPhotoSelectChangedListener = this.imageSelectChangedListener;
        if (onPhotoSelectChangedListener != null) {
            onPhotoSelectChangedListener.onChange(this.selectData);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:49:0x0067, code lost:
    
        if (r10.selectionMode != 1) goto L30;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0077, code lost:
    
        if (r7.selectionMode != 1) goto L37;
     */
    /* JADX WARN: Removed duplicated region for block: B:24:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00e1  */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void m4537c(com.luck.picture.lib.entity.LocalMedia r6, java.lang.String r7, int r8, com.luck.picture.lib.adapter.PictureImageGridAdapter.ViewHolder r9, android.view.View r10) {
        /*
            Method dump skipped, instructions count: 229
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.adapter.PictureImageGridAdapter.m4537c(com.luck.picture.lib.entity.LocalMedia, java.lang.String, int, com.luck.picture.lib.adapter.PictureImageGridAdapter$ViewHolder, android.view.View):void");
    }

    public void clear() {
        if (getSize() > 0) {
            this.data.clear();
        }
    }

    public List<LocalMedia> getData() {
        List<LocalMedia> list = this.data;
        return list == null ? new ArrayList() : list;
    }

    public LocalMedia getItem(int i2) {
        if (getSize() > 0) {
            return this.data.get(i2);
        }
        return null;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.showCamera ? this.data.size() + 1 : this.data.size();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i2) {
        return (this.showCamera && i2 == 0) ? 1 : 2;
    }

    public List<LocalMedia> getSelectedData() {
        List<LocalMedia> list = this.selectData;
        return list == null ? new ArrayList() : list;
    }

    public int getSelectedSize() {
        List<LocalMedia> list = this.selectData;
        if (list == null) {
            return 0;
        }
        return list.size();
    }

    public int getSize() {
        List<LocalMedia> list = this.data;
        if (list == null) {
            return 0;
        }
        return list.size();
    }

    public boolean isDataEmpty() {
        List<LocalMedia> list = this.data;
        return list == null || list.size() == 0;
    }

    public boolean isSelected(LocalMedia localMedia) {
        int size = this.selectData.size();
        for (int i2 = 0; i2 < size; i2++) {
            LocalMedia localMedia2 = this.selectData.get(i2);
            if (localMedia2 != null && !TextUtils.isEmpty(localMedia2.getPath()) && (localMedia2.getPath().equals(localMedia.getPath()) || localMedia2.getId() == localMedia.getId())) {
                return true;
            }
        }
        return false;
    }

    public boolean isShowCamera() {
        return this.showCamera;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(@NotNull RecyclerView.ViewHolder viewHolder, final int i2) {
        if (getItemViewType(i2) == 1) {
            ((CameraViewHolder) viewHolder).itemView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.h0.b
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    PictureImageGridAdapter.this.m4535a(view);
                }
            });
            return;
        }
        final ViewHolder viewHolder2 = (ViewHolder) viewHolder;
        final LocalMedia localMedia = this.data.get(this.showCamera ? i2 - 1 : i2);
        localMedia.position = viewHolder2.getAdapterPosition();
        String path = localMedia.getPath();
        final String mimeType = localMedia.getMimeType();
        if (this.config.checkNumMode) {
            notifyCheckChanged(viewHolder2, localMedia);
        }
        if (this.config.isSingleDirectReturn) {
            viewHolder2.tvCheck.setVisibility(8);
            viewHolder2.btnCheck.setVisibility(8);
        } else {
            selectImage(viewHolder2, isSelected(localMedia));
            viewHolder2.tvCheck.setVisibility(0);
            viewHolder2.btnCheck.setVisibility(0);
            if (this.config.isMaxSelectEnabledMask) {
                dispatchHandleMask(viewHolder2, localMedia);
            }
        }
        viewHolder2.tvIsGif.setVisibility(PictureMimeType.isGif(mimeType) ? 0 : 8);
        if (PictureMimeType.isHasImage(localMedia.getMimeType())) {
            if (localMedia.loadLongImageStatus == -1) {
                localMedia.isLongImage = MediaUtils.isLongImg(localMedia);
                localMedia.loadLongImageStatus = 0;
            }
            viewHolder2.tvLongChart.setVisibility(localMedia.isLongImage ? 0 : 8);
        } else {
            localMedia.loadLongImageStatus = -1;
            viewHolder2.tvLongChart.setVisibility(8);
        }
        boolean isHasVideo = PictureMimeType.isHasVideo(mimeType);
        if (isHasVideo || PictureMimeType.isHasAudio(mimeType)) {
            viewHolder2.tvDuration.setVisibility(0);
            viewHolder2.tvDuration.setText(DateUtils.formatDurationTime(localMedia.getDuration()));
            PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle == null) {
                viewHolder2.tvDuration.setCompoundDrawablesRelativeWithIntrinsicBounds(isHasVideo ? C3979R.drawable.picture_icon_video : C3979R.drawable.picture_icon_audio, 0, 0, 0);
            } else if (isHasVideo) {
                int i3 = pictureSelectorUIStyle.picture_adapter_item_video_textLeftDrawable;
                if (i3 != 0) {
                    viewHolder2.tvDuration.setCompoundDrawablesRelativeWithIntrinsicBounds(i3, 0, 0, 0);
                } else {
                    viewHolder2.tvDuration.setCompoundDrawablesRelativeWithIntrinsicBounds(C3979R.drawable.picture_icon_video, 0, 0, 0);
                }
            } else {
                int i4 = pictureSelectorUIStyle.picture_adapter_item_audio_textLeftDrawable;
                if (i4 != 0) {
                    viewHolder2.tvDuration.setCompoundDrawablesRelativeWithIntrinsicBounds(i4, 0, 0, 0);
                } else {
                    viewHolder2.tvDuration.setCompoundDrawablesRelativeWithIntrinsicBounds(C3979R.drawable.picture_icon_audio, 0, 0, 0);
                }
            }
        } else {
            viewHolder2.tvDuration.setVisibility(8);
        }
        if (this.config.chooseMode == PictureMimeType.ofAudio()) {
            viewHolder2.ivPicture.setImageResource(C3979R.drawable.picture_audio_placeholder);
        } else {
            ImageEngine imageEngine = PictureSelectionConfig.imageEngine;
            if (imageEngine != null) {
                imageEngine.loadGridImage(this.context, path, viewHolder2.ivPicture);
            }
        }
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.enablePreview || pictureSelectionConfig.enPreviewVideo || pictureSelectionConfig.enablePreviewAudio) {
            viewHolder2.btnCheck.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.h0.c
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    PictureImageGridAdapter.this.m4536b(localMedia, viewHolder2, mimeType, view);
                }
            });
        }
        viewHolder2.contentView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.h0.e
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureImageGridAdapter.this.m4537c(localMedia, mimeType, i2, viewHolder2, view);
            }
        });
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i2) {
        return i2 == 1 ? new CameraViewHolder(LayoutInflater.from(this.context).inflate(C3979R.layout.picture_item_camera, viewGroup, false)) : new ViewHolder(LayoutInflater.from(this.context).inflate(C3979R.layout.picture_image_grid_item, viewGroup, false));
    }

    public void selectImage(ViewHolder viewHolder, boolean z) {
        viewHolder.tvCheck.setSelected(z);
        if (z) {
            viewHolder.ivPicture.setColorFilter(ContextCompat.getColor(this.context, C3979R.color.picture_color_80), PorterDuff.Mode.SRC_ATOP);
        } else {
            viewHolder.ivPicture.setColorFilter(ContextCompat.getColor(this.context, C3979R.color.picture_color_20), PorterDuff.Mode.SRC_ATOP);
        }
    }

    public void setOnPhotoSelectChangedListener(OnPhotoSelectChangedListener onPhotoSelectChangedListener) {
        this.imageSelectChangedListener = onPhotoSelectChangedListener;
    }

    public void setShowCamera(boolean z) {
        this.showCamera = z;
    }
}
