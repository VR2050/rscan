package im.uwrkaxlmjj.ui.hui.friendscircle_v1.base;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.exifinterface.media.ExifInterface;
import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FcMediaResponseBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.presenter.FcCommonPresenter;
import com.bjz.comm.net.utils.HttpUtils;
import com.gyf.barlibrary.ImmersionBar;
import com.gyf.barlibrary.OnKeyboardListener;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hui.discovery.ActionIntroActivity;
import im.uwrkaxlmjj.ui.hui.discovery.NearPersonAndGroupActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper.FcDBHelper;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.TimeUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONException;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public abstract class BaseFcActivity extends BaseFragment implements BaseFcContract.IFcCommView {
    protected int currentAccount = UserConfig.selectedAccount;
    public String currentPicturePath;
    private FcCommMenuDialog dialogCommonList;
    private FcCommonPresenter mCommPresenter;
    protected Context mContext;
    protected ImmersionBar mImmersionBar;
    protected Dialog visibleDialog;

    protected abstract int getLayoutRes();

    protected abstract void initData();

    protected abstract void initView();

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(getLayoutRes(), (ViewGroup) null);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.fragmentView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.-$$Lambda$BaseFcActivity$PXPuSEL1aYAmilrG5ilm2E8RquM
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return BaseFcActivity.lambda$createView$0(view, motionEvent);
            }
        });
        initView();
        initData();
        convertFontToBold((ViewGroup) this.fragmentView.getRootView());
        setBackground((ViewGroup) this.fragmentView.getRootView());
        this.mCommPresenter = new FcCommonPresenter(this);
        return this.fragmentView;
    }

    static /* synthetic */ boolean lambda$createView$0(View v, MotionEvent event) {
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        ImmersionBar immersionBar = this.mImmersionBar;
        if (immersionBar != null) {
            immersionBar.destroy();
        }
        FcCommonPresenter fcCommonPresenter = this.mCommPresenter;
        if (fcCommonPresenter != null) {
            fcCommonPresenter.unSubscribeTask();
        }
    }

    protected void initImmersionBar() {
        ImmersionBar immersionBarWith = ImmersionBar.with((Activity) this.mContext);
        this.mImmersionBar = immersionBarWith;
        immersionBarWith.transparentStatusBar().transparentNavigationBar().transparentBar().statusBarAlpha(0.3f).navigationBarAlpha(0.4f).barAlpha(0.3f).flymeOSStatusBarFontColor(R.color.color_text_black_000000).fullScreen(true).fitsSystemWindows(true).supportActionBar(true).removeSupportAllView().addTag("tag").getTag("tag").reset().keyboardEnable(false).setOnKeyboardListener(new OnKeyboardListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity.1
            @Override // com.gyf.barlibrary.OnKeyboardListener
            public void onKeyboardChange(boolean isPopup, int keyboardHeight) {
            }
        }).keyboardMode(16).init();
    }

    protected void initActionBar(String title) {
        if (!TextUtils.isEmpty(title)) {
            this.actionBar.setTitle(title);
            this.actionBar.setBackButtonImage(R.id.ic_back_white);
            this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity.2
                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
                public void onItemClick(int id) {
                    if (id == -1) {
                        BaseFcActivity.this.finishFragment();
                    }
                }
            });
        }
    }

    private void convertFontToBold(ViewGroup viewGroup) {
        if (viewGroup != null) {
            int count = viewGroup.getChildCount();
            for (int i = 0; i < count; i++) {
                View view = viewGroup.getChildAt(i);
                if (view instanceof ViewGroup) {
                    convertFontToBold((ViewGroup) view);
                } else if (this.mContext.getResources().getString(R.string.Typeface_Bold).equals(view.getTag())) {
                    if (view instanceof TextView) {
                        ((TextView) view).setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                    } else if (view instanceof EditText) {
                        ((EditText) view).setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                    }
                }
            }
        }
    }

    private void setBackground(ViewGroup viewGroup) {
        int count = viewGroup.getChildCount();
        for (int i = 0; i < count; i++) {
            View view = viewGroup.getChildAt(i);
            Object tag = view.getTag();
            if (tag != null) {
                String key = (String) tag;
                byte b = -1;
                int iHashCode = key.hashCode();
                if (iHashCode != -1397026623) {
                    if (iHashCode != -343666293) {
                        if (iHashCode == 1658529622 && key.equals(Theme.key_walletDefaultBackground)) {
                            b = 2;
                        }
                    } else if (key.equals(Theme.key_windowBackgroundWhite)) {
                        b = 0;
                    }
                } else if (key.equals(Theme.key_windowBackgroundGray)) {
                    b = 1;
                }
                if (b == 0) {
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                } else if (b == 1) {
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                } else if (b == 2) {
                    view.setBackgroundColor(Theme.getColor(Theme.key_walletDefaultBackground));
                }
            }
            if (view instanceof ViewGroup) {
                setBackground((ViewGroup) view);
            }
        }
    }

    public BaseFragment getCurrentFragment() {
        return getParentLayout().getCurrentFragment();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public Dialog showDialog(Dialog dialog) {
        return showDialog(dialog, false, null);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public Dialog showDialog(Dialog dialog, DialogInterface.OnDismissListener onDismissListener) {
        return showDialog(dialog, false, onDismissListener);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public Dialog showDialog(Dialog dialog, boolean allowInTransition, final DialogInterface.OnDismissListener onDismissListener) {
        if (dialog == null || this.parentLayout == null || (!allowInTransition && this.parentLayout.checkTransitionAnimation())) {
            return null;
        }
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            this.visibleDialog = dialog;
            dialog.setCanceledOnTouchOutside(true);
            this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.-$$Lambda$BaseFcActivity$yqt4Uz_oKNPqTII9Ql8DDx3g560
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$showDialog$1$BaseFcActivity(onDismissListener, dialogInterface);
                }
            });
            this.visibleDialog.show();
            return this.visibleDialog;
        } catch (Exception e2) {
            FileLog.e(e2);
            return null;
        }
    }

    public /* synthetic */ void lambda$showDialog$1$BaseFcActivity(DialogInterface.OnDismissListener onDismissListener, DialogInterface dialog1) {
        if (onDismissListener != null) {
            onDismissListener.onDismiss(dialog1);
        }
        onDialogDismiss(this.visibleDialog);
        this.visibleDialog = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void dismissCurrentDialog() {
        Dialog dialog = this.visibleDialog;
        if (dialog == null) {
            return;
        }
        try {
            dialog.dismiss();
            this.visibleDialog = null;
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public Dialog getVisibleDialog() {
        return this.visibleDialog;
    }

    protected void showResetFcBgDialog() {
        if (getParentActivity() != null) {
            if (this.dialogCommonList == null) {
                List<String> list = new ArrayList<>();
                list.add("从手机相册选择");
                list.add("拍一张");
                FcCommMenuDialog fcCommMenuDialog = new FcCommMenuDialog(getParentActivity(), list, (List<Integer>) null, Theme.getColor(Theme.key_windowBackgroundWhiteBlackText), new FcCommMenuDialog.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity.3
                    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.RecyclerviewItemClickCallBack
                    public void onRecyclerviewItemClick(int position) {
                        if (position == 0) {
                            BaseFcActivity.this.openGallery();
                        } else if (position == 1) {
                            BaseFcActivity.this.openCamera();
                        }
                    }
                }, 1);
                this.dialogCommonList = fcCommMenuDialog;
                fcCommMenuDialog.setTitle(LocaleController.getString("fc_change_bg", R.string.fc_change_bg), -7631463, 15);
            }
            if (this.dialogCommonList.isShowing()) {
                this.dialogCommonList.dismiss();
            } else {
                this.dialogCommonList.show();
            }
        }
    }

    public void openGallery() {
        if (Build.VERSION.SDK_INT >= 23 && getParentActivity() != null && getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0) {
            getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 4);
            return;
        }
        PhotoAlbumPickerActivity fragment = new PhotoAlbumPickerActivity(1, false, false, null, true);
        fragment.setDelegate(new PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity.4
            @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
            public void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> photos, boolean notify, int scheduleDate, boolean blnOriginalImg) {
                if (photos.get(0) != null) {
                    KLog.d("-------相册的背景图-" + photos.get(0).path);
                    BaseFcActivity.this.didSelectOnePhoto(photos.get(0).path);
                }
            }

            @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
            public void startPhotoSelectActivity() {
            }
        });
        presentFragment(fragment);
    }

    public void openCamera() {
        if (getParentActivity() == null) {
            return;
        }
        try {
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission("android.permission.CAMERA") != 0) {
                getParentActivity().requestPermissions(new String[]{"android.permission.CAMERA"}, 19);
                return;
            }
            Intent takePictureIntent = new Intent("android.media.action.IMAGE_CAPTURE");
            File image = AndroidUtilities.generatePicturePath();
            if (image != null) {
                if (Build.VERSION.SDK_INT >= 24) {
                    takePictureIntent.putExtra("output", FileProvider.getUriForFile(getParentActivity(), "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", image));
                    takePictureIntent.addFlags(2);
                    takePictureIntent.addFlags(1);
                } else {
                    takePictureIntent.putExtra("output", Uri.fromFile(image));
                }
                this.currentPicturePath = image.getAbsolutePath();
            }
            startActivityForResult(takePictureIntent, 133);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        super.onActivityResultFragment(requestCode, resultCode, data);
        if (resultCode == -1 && requestCode == 133) {
            PhotoViewer.getInstance().setParentActivity(getParentActivity());
            int orientation = 0;
            try {
                ExifInterface ei = new ExifInterface(this.currentPicturePath);
                int exif = ei.getAttributeInt(ExifInterface.TAG_ORIENTATION, 1);
                if (exif == 3) {
                    orientation = JavaScreenCapturer.DEGREE_180;
                } else if (exif == 6) {
                    orientation = 90;
                } else if (exif == 8) {
                    orientation = JavaScreenCapturer.DEGREE_270;
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            final ArrayList<Object> arrayList = new ArrayList<>();
            arrayList.add(new MediaController.PhotoEntry(0, 0, 0L, this.currentPicturePath, orientation, false));
            PhotoViewer.getInstance().setIsFcCrop(true);
            PhotoViewer.getInstance().openPhotoForSelect(arrayList, 0, 1, new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity.5
                @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
                    String path = null;
                    MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) arrayList.get(0);
                    if (photoEntry.imagePath != null) {
                        path = photoEntry.imagePath;
                    } else if (photoEntry.path != null) {
                        path = photoEntry.path;
                    }
                    KLog.d("-------拍照的背景图-" + path);
                    BaseFcActivity.this.didSelectOnePhoto(path);
                }

                @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                public boolean allowCaption() {
                    return false;
                }

                @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                public boolean canScrollAway() {
                    return false;
                }
            }, null);
            AndroidUtilities.addMediaToGallery(this.currentPicturePath);
            this.currentPicturePath = null;
        }
    }

    protected void didSelectOnePhoto(String photosPath) {
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void getUploadUrlFailed(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_fail_to_get_ip_location", R.string.friendscircle_fail_to_get_ip_location) : msg));
    }

    protected void uploadFile(String path, DataListener<BResponse<FcMediaResponseBean>> listener) {
        if (!TextUtils.isEmpty(path)) {
            File file = new File(path);
            if (file.exists()) {
                this.mCommPresenter.uploadFile(file, listener);
            }
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onUploadFileSucc(FcMediaResponseBean data, String msg) {
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onUploadFileError(String msg) {
    }

    protected void downloadFileToLocal(final String path) {
        String tips = LocaleController.getString(R.string.save_pic);
        String suffix = ".jpg";
        if (!TextUtils.isEmpty(path)) {
            if (path.toLowerCase().endsWith(".mp4")) {
                tips = LocaleController.getString(R.string.save_video);
                suffix = ".mp4";
            } else if (path.toLowerCase().endsWith(".gif")) {
                tips = LocaleController.getString(R.string.save_pic);
                suffix = ".gif";
            } else {
                tips = LocaleController.getString(R.string.save_pic);
                suffix = ".jpg";
            }
        }
        List<String> list = new ArrayList<>();
        list.add(tips);
        final String finalSuffix = suffix;
        FcCommMenuDialog dialogCommonList = new FcCommMenuDialog(getParentActivity(), list, (List<Integer>) null, Theme.getColor(Theme.key_windowBackgroundWhiteBlackText), new FcCommMenuDialog.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity.6
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.RecyclerviewItemClickCallBack
            public void onRecyclerviewItemClick(int position) {
                if (position == 0) {
                    BaseFcActivity.this.mCommPresenter.downloadFile(HttpUtils.getInstance().getDownloadFileUrl() + path, AndroidUtilities.getAlbumDir(false).getAbsolutePath(), TimeUtils.getCurrentTime() + finalSuffix);
                }
            }
        }, 1);
        dialogCommonList.show();
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onDownloadFileSucc(File file) {
        AndroidUtilities.addMediaToGallery(Uri.fromFile(file));
        FcToastUtils.show((CharSequence) LocaleController.getString(R.string.save_album_success));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onDownloadFileError(String msg) {
        FcToastUtils.show((CharSequence) LocaleController.getString(R.string.save_album_error));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onError(String msg) {
    }

    protected <T> void saveNewFcToLocal(T t) {
        FcDBHelper.getInstance().insert(t);
    }

    protected <T> void updateLocalFollowStatus(Class<T> cla, long createBy, boolean isFollow) {
        FcDBHelper.getInstance().updateItemFollowStatus(cla, createBy, isFollow);
    }

    protected <T> void updateLocalItemPermissionStatus(Class<T> cla, long forumID, int permission) {
        FcDBHelper.getInstance().updateItemPermissionStatus(cla, forumID, permission);
    }

    protected <T> void deleteLocalItemById(Class<T> cla, long forumId) throws JSONException {
        FcDBHelper.getInstance().deleteItemById(cla, forumId);
    }

    protected <T> void deleteLocalItemByUserId(Class<T> cla, long userId) throws JSONException {
        FcDBHelper.getInstance().deleteItemByUserId(cla, userId);
    }

    protected <T> void updateLocalItemLikeStatus(Class<T> cla, long forumId, boolean isLike, int ThumbUp) {
        FcDBHelper.getInstance().updateItemLikeStatus(cla, forumId, isLike, ThumbUp);
    }

    protected <T> void updateLocalReplyStatus(Class<T> cla, long forumID, FcReplyBean mFcReplyBean) {
        KLog.d("------------------添加" + forumID);
        FcDBHelper.getInstance().updateItemReply(cla, forumID, mFcReplyBean);
    }

    protected <T> void deleteLocalReply(Class<T> cla, long forumID, long commentID, int commentCount) throws JSONException {
        FcDBHelper.getInstance().deleteReply(cla, forumID, commentID, commentCount);
    }

    public void goToNearBy() {
        Activity activity;
        if (Build.VERSION.SDK_INT >= 23 && (activity = getParentActivity()) != null && activity.checkSelfPermission(PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION) != 0) {
            presentFragment(new ActionIntroActivity(1));
            return;
        }
        boolean enabled = true;
        if (Build.VERSION.SDK_INT >= 28) {
            LocationManager lm = (LocationManager) ApplicationLoader.applicationContext.getSystemService("location");
            enabled = lm.isLocationEnabled();
        } else if (Build.VERSION.SDK_INT >= 19) {
            try {
                int mode = Settings.Secure.getInt(ApplicationLoader.applicationContext.getContentResolver(), "location_mode", 0);
                enabled = mode != 0;
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
        if (!enabled) {
            presentFragment(new ActionIntroActivity(4));
        } else {
            presentFragment(new NearPersonAndGroupActivity());
        }
    }
}
