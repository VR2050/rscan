package com.luck.picture.lib.widget;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.PopupWindow;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.adapter.PictureAlbumDirectoryAdapter;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.entity.LocalMediaFolder;
import com.luck.picture.lib.listener.OnAlbumItemClickListener;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import com.luck.picture.lib.tools.AnimUtils;
import com.luck.picture.lib.tools.AttrsUtils;
import com.luck.picture.lib.tools.ScreenUtils;
import com.luck.picture.lib.widget.FolderPopWindow;
import java.util.List;

/* loaded from: classes2.dex */
public class FolderPopWindow extends PopupWindow {
    private PictureAlbumDirectoryAdapter adapter;
    private int chooseMode;
    private PictureSelectionConfig config;
    private Context context;
    private Drawable drawableDown;
    private Drawable drawableUp;
    private boolean isDismiss = false;
    private ImageView ivArrowView;
    private RecyclerView mRecyclerView;
    private int maxHeight;
    private View rootViewBg;
    private View window;

    public FolderPopWindow(Context context) {
        this.context = context;
        PictureSelectionConfig pictureSelectionConfig = PictureSelectionConfig.getInstance();
        this.config = pictureSelectionConfig;
        this.chooseMode = pictureSelectionConfig.chooseMode;
        View inflate = LayoutInflater.from(context).inflate(C3979R.layout.picture_window_folder, (ViewGroup) null);
        this.window = inflate;
        setContentView(inflate);
        setWidth(-1);
        setHeight(-2);
        setAnimationStyle(C3979R.style.PictureThemeWindowStyle);
        setFocusable(true);
        setOutsideTouchable(true);
        update();
        PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle != null) {
            int i2 = pictureSelectorUIStyle.picture_top_titleArrowUpDrawable;
            if (i2 != 0) {
                this.drawableUp = ContextCompat.getDrawable(context, i2);
            }
            int i3 = PictureSelectionConfig.uiStyle.picture_top_titleArrowDownDrawable;
            if (i3 != 0) {
                this.drawableDown = ContextCompat.getDrawable(context, i3);
            }
        } else {
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle != null) {
                int i4 = pictureParameterStyle.pictureTitleUpResId;
                if (i4 != 0) {
                    this.drawableUp = ContextCompat.getDrawable(context, i4);
                }
                int i5 = PictureSelectionConfig.style.pictureTitleDownResId;
                if (i5 != 0) {
                    this.drawableDown = ContextCompat.getDrawable(context, i5);
                }
            } else {
                PictureSelectionConfig pictureSelectionConfig2 = this.config;
                if (pictureSelectionConfig2.isWeChatStyle) {
                    this.drawableUp = ContextCompat.getDrawable(context, C3979R.drawable.picture_icon_wechat_up);
                    this.drawableDown = ContextCompat.getDrawable(context, C3979R.drawable.picture_icon_wechat_down);
                } else {
                    int i6 = pictureSelectionConfig2.upResId;
                    if (i6 != 0) {
                        this.drawableUp = ContextCompat.getDrawable(context, i6);
                    } else {
                        this.drawableUp = AttrsUtils.getTypeValueDrawable(context, C3979R.attr.picture_arrow_up_icon, C3979R.drawable.picture_icon_arrow_up);
                    }
                    int i7 = this.config.downResId;
                    if (i7 != 0) {
                        this.drawableDown = ContextCompat.getDrawable(context, i7);
                    } else {
                        this.drawableDown = AttrsUtils.getTypeValueDrawable(context, C3979R.attr.picture_arrow_down_icon, C3979R.drawable.picture_icon_arrow_down);
                    }
                }
            }
        }
        this.maxHeight = (int) (ScreenUtils.getScreenHeight(context) * 0.6d);
        initView();
    }

    public void bindFolder(List<LocalMediaFolder> list) {
        this.adapter.setChooseMode(this.chooseMode);
        this.adapter.bindFolderData(list);
        this.mRecyclerView.getLayoutParams().height = (list == null || list.size() <= 8) ? -2 : this.maxHeight;
    }

    @Override // android.widget.PopupWindow
    public void dismiss() {
        if (this.isDismiss) {
            return;
        }
        this.rootViewBg.animate().alpha(0.0f).setDuration(50L).start();
        this.ivArrowView.setImageDrawable(this.drawableDown);
        AnimUtils.rotateArrow(this.ivArrowView, false);
        this.isDismiss = true;
        super.dismiss();
        this.isDismiss = false;
    }

    public LocalMediaFolder getFolder(int i2) {
        if (this.adapter.getFolderData().size() <= 0 || i2 >= this.adapter.getFolderData().size()) {
            return null;
        }
        return this.adapter.getFolderData().get(i2);
    }

    public List<LocalMediaFolder> getFolderData() {
        return this.adapter.getFolderData();
    }

    public void initView() {
        this.rootViewBg = this.window.findViewById(C3979R.id.rootViewBg);
        this.adapter = new PictureAlbumDirectoryAdapter(this.config);
        RecyclerView recyclerView = (RecyclerView) this.window.findViewById(C3979R.id.folder_list);
        this.mRecyclerView = recyclerView;
        recyclerView.setLayoutManager(new LinearLayoutManager(this.context));
        this.mRecyclerView.setAdapter(this.adapter);
        this.window.findViewById(C3979R.id.rootView);
        this.rootViewBg.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.l0.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                FolderPopWindow.this.dismiss();
            }
        });
    }

    public boolean isEmpty() {
        return this.adapter.getFolderData().size() == 0;
    }

    public void setArrowImageView(ImageView imageView) {
        this.ivArrowView = imageView;
    }

    public void setOnAlbumItemClickListener(OnAlbumItemClickListener onAlbumItemClickListener) {
        this.adapter.setOnAlbumItemClickListener(onAlbumItemClickListener);
    }

    @Override // android.widget.PopupWindow
    public void showAsDropDown(View view) {
        try {
            if (Build.VERSION.SDK_INT == 24) {
                int[] iArr = new int[2];
                view.getLocationInWindow(iArr);
                showAtLocation(view, 0, 0, iArr[1] + view.getHeight());
            } else {
                super.showAsDropDown(view);
            }
            this.isDismiss = false;
            this.ivArrowView.setImageDrawable(this.drawableUp);
            AnimUtils.rotateArrow(this.ivArrowView, true);
            this.rootViewBg.animate().alpha(1.0f).setDuration(250L).setStartDelay(250L).start();
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void updateFolderCheckStatus(List<LocalMedia> list) {
        int i2;
        try {
            List<LocalMediaFolder> folderData = this.adapter.getFolderData();
            int size = folderData.size();
            int size2 = list.size();
            for (int i3 = 0; i3 < size; i3++) {
                LocalMediaFolder localMediaFolder = folderData.get(i3);
                localMediaFolder.setCheckedNum(0);
                while (i2 < size2) {
                    i2 = (localMediaFolder.getName().equals(list.get(i2).getParentFolderName()) || localMediaFolder.getBucketId() == -1) ? 0 : i2 + 1;
                    localMediaFolder.setCheckedNum(1);
                    break;
                }
            }
            this.adapter.bindFolderData(folderData);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }
}
