package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Outline;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.hardware.Camera;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputFilter;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.Property;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.messenger.camera.CameraController;
import im.uwrkaxlmjj.messenger.camera.CameraView;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.PhotoAttachCameraCell;
import im.uwrkaxlmjj.ui.cells.PhotoAttachPermissionCell;
import im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.EditTextEmoji;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector;
import im.uwrkaxlmjj.ui.components.ShutterButton;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import im.uwrkaxlmjj.ui.components.ZoomControlView;
import im.uwrkaxlmjj.ui.hui.adapter.EditInputFilter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class ImagePreSelectorActivity extends BottomSheet implements NotificationCenter.NotificationCenterDelegate, BottomSheet.BottomSheetDelegateInterface {
    public static final int SELECT_TYPE_GIF = 3;
    public static final int SELECT_TYPE_IMG = 1;
    public static final int SELECT_TYPE_NONE = 0;
    public static final int SELECT_TYPE_VIDEO = 2;
    private static final int compress = 1;
    private static final int group = 0;
    private static final int isSkip = 3;
    private static boolean mediaFromExternalCamera;
    private final int VIDEO_TIME_LENGTH;
    private ActionBar actionBar;
    private AnimatorSet actionBarAnimation;
    private View actionBarShadow;
    private PhotoAttachAdapter adapter;
    private boolean allowOrder;
    private int[] animateCameraValues;
    private AnimatorSet animatorSet;
    private boolean buttonPressed;
    private boolean cameraAnimationInProgress;
    private PhotoAttachAdapter cameraAttachAdapter;
    private Drawable cameraDrawable;
    private FrameLayout cameraIcon;
    private AnimatorSet cameraInitAnimation;
    private float cameraOpenProgress;
    private boolean cameraOpened;
    private FrameLayout cameraPanel;
    private LinearLayoutManager cameraPhotoLayoutManager;
    private RecyclerListView cameraPhotoRecyclerView;
    private boolean cameraPhotoRecyclerViewIgnoreLayout;
    private CameraView cameraView;
    private int[] cameraViewLocation;
    private int cameraViewOffsetBottomY;
    private int cameraViewOffsetX;
    private int cameraViewOffsetY;
    private float cameraZoom;
    private boolean cancelTakingPhotos;
    private EditTextEmoji commentTextView;
    private float cornerRadius;
    private TextView counterTextView;
    private int currentAccount;
    private int currentSelectMediaType;
    private int currentSelectedCount;
    private ChatAttachViewDelegate delegate;
    private boolean deviceHasGoodCamera;
    private boolean dragging;
    private TextView dropDown;
    private ArrayList<MediaController.AlbumEntry> dropDownAlbums;
    private ActionBarMenuItem dropDownContainer;
    private Drawable dropDownDrawable;
    private MessageObject editingMessageObject;
    private boolean enterCommentEventSent;
    private boolean flashAnimationInProgress;
    private ImageView[] flashModeButton;
    private MediaController.AlbumEntry galleryAlbumEntry;
    private int gridExtraSpace;
    private RecyclerListView gridView;
    private Rect hitRect;
    private DecelerateInterpolator interpolator;
    private final ActionBarMenuItem isSkipMenu;
    private RecyclerViewItemRangeSelector itemRangeSelector;
    private int itemSize;
    private int itemsPerRow;
    private int lastItemSize;
    private float lastY;
    private GridLayoutManager layoutManager;
    private boolean loading;
    private Activity mActivity;
    private int maxSelectedPhotos;
    private boolean maybeStartDraging;
    private boolean mediaCaptured;
    private boolean mediaEnabled;
    private boolean noCameraPermissions;
    private boolean noGalleryPermissions;
    private boolean openWithFrontFaceCamera;
    private boolean paused;
    private ImagePreviewActivity.PhotoViewerProvider photoViewerProvider;
    private float pinchStartDistance;
    private boolean pressed;
    private EmptyTextProgressView progressView;
    private TextView recordTime;
    private boolean requestingPermissions;
    private int scrollOffsetY;
    private MediaController.AlbumEntry selectedAlbumEntry;
    private TextView selectedTextView;
    private boolean shouldSelect;
    private ShutterButton shutterButton;
    private SizeNotifierFrameLayout sizeNotifierFrameLayout;
    private ImageView switchCameraButton;
    private boolean takingPhoto;
    private TextPaint textPaint;
    private TextView tooltipTextView;
    private Runnable videoRecordRunnable;
    private int videoRecordTime;
    private int[] viewPosition;
    private ImageView writeButton;
    private FrameLayout writeButtonContainer;
    private Drawable writeButtonDrawable;
    private AnimatorSet zoomControlAnimation;
    private Runnable zoomControlHideRunnable;
    private ZoomControlView zoomControlView;
    private boolean zoomWas;
    private boolean zooming;
    private static ArrayList<Object> cameraPhotos = new ArrayList<>();
    private static HashMap<Object, Object> selectedPhotos = new HashMap<>();
    private static ArrayList<Object> selectedPhotosOrder = new ArrayList<>();
    private static int lastImageId = -1;

    public interface ChatAttachViewDelegate {
        void didPressedButton(int i, boolean z, boolean z2, int i2);

        void didSelectBot(TLRPC.User user);

        View getRevealView();

        void needEnterComment();

        void onCameraOpened();
    }

    static /* synthetic */ int access$7108(ImagePreSelectorActivity x0) {
        int i = x0.videoRecordTime;
        x0.videoRecordTime = i + 1;
        return i;
    }

    static /* synthetic */ int access$8010() {
        int i = lastImageId;
        lastImageId = i - 1;
        return i;
    }

    public ArrayList<MediaController.AlbumEntry> getDropDownAlbums() {
        return this.dropDownAlbums;
    }

    private class BasePhotoProvider extends ImagePreviewActivity.EmptyPhotoViewerProvider {
        private BasePhotoProvider() {
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean isPhotoChecked(int index) {
            MediaController.PhotoEntry photoEntry = ImagePreSelectorActivity.this.getPhotoEntryAtPosition(index);
            return photoEntry != null && ImagePreSelectorActivity.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId));
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public int setPhotoChecked(int index, VideoEditedInfo videoEditedInfo) {
            MediaController.PhotoEntry photoEntry;
            if ((ImagePreSelectorActivity.this.maxSelectedPhotos >= 0 && ImagePreSelectorActivity.selectedPhotos.size() >= ImagePreSelectorActivity.this.maxSelectedPhotos && !isPhotoChecked(index)) || (photoEntry = ImagePreSelectorActivity.this.getPhotoEntryAtPosition(index)) == null) {
                return -1;
            }
            boolean add = true;
            int iAddToSelectedPhotos = ImagePreSelectorActivity.this.addToSelectedPhotos(photoEntry, -1);
            int num = iAddToSelectedPhotos;
            if (iAddToSelectedPhotos == -1) {
                num = ImagePreSelectorActivity.selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry.imageId));
            } else {
                add = false;
                photoEntry.editedInfo = null;
            }
            photoEntry.editedInfo = videoEditedInfo;
            int count = ImagePreSelectorActivity.this.gridView.getChildCount();
            int a = 0;
            while (true) {
                if (a >= count) {
                    break;
                }
                View view = ImagePreSelectorActivity.this.gridView.getChildAt(a);
                if (view instanceof PhotoAttachPhotoCell) {
                    int tag = ((Integer) view.getTag()).intValue();
                    if (tag == index) {
                        ((PhotoAttachPhotoCell) view).setChecked(-1, add, false);
                        break;
                    }
                }
                a++;
            }
            int count2 = ImagePreSelectorActivity.this.cameraPhotoRecyclerView.getChildCount();
            int a2 = 0;
            while (true) {
                if (a2 >= count2) {
                    break;
                }
                View view2 = ImagePreSelectorActivity.this.cameraPhotoRecyclerView.getChildAt(a2);
                if (view2 instanceof PhotoAttachPhotoCell) {
                    int tag2 = ((Integer) view2.getTag()).intValue();
                    if (tag2 == index) {
                        ((PhotoAttachPhotoCell) view2).setChecked(-1, add, false);
                        break;
                    }
                }
                a2++;
            }
            ImagePreSelectorActivity.this.updatePhotosButton();
            return num;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public int getSelectedCount() {
            return ImagePreSelectorActivity.selectedPhotos.size();
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public ArrayList<Object> getSelectedPhotosOrder() {
            return ImagePreSelectorActivity.selectedPhotosOrder;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public HashMap<Object, Object> getSelectedPhotos() {
            return ImagePreSelectorActivity.selectedPhotos;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public int getPhotoIndex(int index) {
            MediaController.PhotoEntry photoEntry = ImagePreSelectorActivity.this.getPhotoEntryAtPosition(index);
            if (photoEntry != null) {
                return ImagePreSelectorActivity.selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry.imageId));
            }
            return -1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (Build.VERSION.SDK_INT >= 22 && isLightColor(Theme.getColor(Theme.key_dialogBackground))) {
            getWindow().getDecorView().setSystemUiVisibility(9216);
        }
    }

    public boolean isLightColor(int color) {
        double darkness = 1.0d - ((((((double) Color.red(color)) * 0.299d) + (((double) Color.green(color)) * 0.587d)) + (((double) Color.blue(color)) * 0.114d)) / 255.0d);
        if (darkness < 0.5d) {
            return true;
        }
        return false;
    }

    private void updateCheckedPhotoIndices() {
        int count = this.gridView.getChildCount();
        for (int a = 0; a < count; a++) {
            View view = this.gridView.getChildAt(a);
            if (view instanceof PhotoAttachPhotoCell) {
                PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                MediaController.PhotoEntry photoEntry = getPhotoEntryAtPosition(((Integer) cell.getTag()).intValue());
                if (photoEntry != null) {
                    cell.setNum(selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry.imageId)));
                }
            }
        }
        int count2 = this.cameraPhotoRecyclerView.getChildCount();
        for (int a2 = 0; a2 < count2; a2++) {
            View view2 = this.cameraPhotoRecyclerView.getChildAt(a2);
            if (view2 instanceof PhotoAttachPhotoCell) {
                PhotoAttachPhotoCell cell2 = (PhotoAttachPhotoCell) view2;
                MediaController.PhotoEntry photoEntry2 = getPhotoEntryAtPosition(((Integer) cell2.getTag()).intValue());
                if (photoEntry2 != null) {
                    cell2.setNum(selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry2.imageId)));
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public MediaController.PhotoEntry getPhotoEntryAtPosition(int position) {
        if (position < 0) {
            return null;
        }
        int cameraCount = cameraPhotos.size();
        if (position < cameraCount) {
            return (MediaController.PhotoEntry) cameraPhotos.get(position);
        }
        int position2 = position - cameraCount;
        if (position2 >= this.selectedAlbumEntry.photos.size()) {
            return null;
        }
        return this.selectedAlbumEntry.photos.get(position2);
    }

    private ArrayList<Object> getAllPhotosArray() {
        if (this.selectedAlbumEntry != null) {
            if (!cameraPhotos.isEmpty()) {
                ArrayList<Object> arrayList = new ArrayList<>(this.selectedAlbumEntry.photos.size() + cameraPhotos.size());
                arrayList.addAll(cameraPhotos);
                arrayList.addAll(this.selectedAlbumEntry.photos);
                return arrayList;
            }
            ArrayList<Object> arrayList2 = this.selectedAlbumEntry.photos;
            return arrayList2;
        }
        ArrayList<Object> arrayList3 = cameraPhotos;
        if (!arrayList3.isEmpty()) {
            ArrayList<Object> arrayList4 = cameraPhotos;
            return arrayList4;
        }
        ArrayList<Object> arrayList5 = new ArrayList<>(0);
        return arrayList5;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public ImagePreSelectorActivity(Activity activity) {
        super(activity, false, 1);
        int i = 0;
        Object[] objArr = 0;
        this.textPaint = new TextPaint(1);
        this.cornerRadius = 1.0f;
        this.currentAccount = UserConfig.selectedAccount;
        this.mediaEnabled = true;
        this.flashModeButton = new ImageView[2];
        this.cameraViewLocation = new int[2];
        this.viewPosition = new int[2];
        this.animateCameraValues = new int[5];
        this.interpolator = new DecelerateInterpolator(1.5f);
        this.maxSelectedPhotos = 9;
        this.allowOrder = true;
        this.hitRect = new Rect();
        int iDp = AndroidUtilities.dp(80.0f);
        this.itemSize = iDp;
        this.lastItemSize = iDp;
        this.itemsPerRow = 3;
        this.loading = true;
        this.VIDEO_TIME_LENGTH = 59;
        this.currentSelectMediaType = 0;
        this.photoViewerProvider = new BasePhotoProvider() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.1
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
            public ImagePreviewActivity.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
                PhotoAttachPhotoCell cell = ImagePreSelectorActivity.this.getCellForIndex(index);
                if (cell != null) {
                    int[] coords = new int[2];
                    cell.getImageView().getLocationInWindow(coords);
                    if (Build.VERSION.SDK_INT < 26) {
                        coords[0] = coords[0] - ImagePreSelectorActivity.this.getLeftInset();
                    }
                    ImagePreviewActivity.PlaceProviderObject object = new ImagePreviewActivity.PlaceProviderObject();
                    object.viewX = coords[0];
                    object.viewY = coords[1];
                    object.parentView = ImagePreSelectorActivity.this.gridView;
                    object.imageReceiver = cell.getImageView().getImageReceiver();
                    object.thumb = object.imageReceiver.getBitmapSafe();
                    object.scale = cell.getScale();
                    cell.showCheck(false);
                    return object;
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
            public void updatePhotoAtIndex(int index) {
                PhotoAttachPhotoCell cell = ImagePreSelectorActivity.this.getCellForIndex(index);
                if (cell != null) {
                    cell.getImageView().setOrientation(0, true);
                    MediaController.PhotoEntry photoEntry = ImagePreSelectorActivity.this.getPhotoEntryAtPosition(index);
                    if (photoEntry == null) {
                        return;
                    }
                    if (photoEntry.thumbPath != null) {
                        cell.getImageView().setImage(photoEntry.thumbPath, null, Theme.chat_attachEmptyDrawable);
                        return;
                    }
                    if (photoEntry.path != null) {
                        cell.getImageView().setOrientation(photoEntry.orientation, true);
                        if (photoEntry.isVideo) {
                            cell.getImageView().setImage("vthumb://" + photoEntry.imageId + LogUtils.COLON + photoEntry.path, null, Theme.chat_attachEmptyDrawable);
                            return;
                        }
                        cell.getImageView().setImage("thumb://" + photoEntry.imageId + LogUtils.COLON + photoEntry.path, null, Theme.chat_attachEmptyDrawable);
                        return;
                    }
                    cell.getImageView().setImageDrawable(Theme.chat_attachEmptyDrawable);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
            public ImageReceiver.BitmapHolder getThumbForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
                PhotoAttachPhotoCell cell = ImagePreSelectorActivity.this.getCellForIndex(index);
                if (cell != null) {
                    return cell.getImageView().getImageReceiver().getBitmapSafe();
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
            public void willSwitchFromPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
                PhotoAttachPhotoCell cell = ImagePreSelectorActivity.this.getCellForIndex(index);
                if (cell != null) {
                    cell.showCheck(true);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
            public void willHidePhotoViewer() {
                int count = ImagePreSelectorActivity.this.gridView.getChildCount();
                for (int a = 0; a < count; a++) {
                    View view = ImagePreSelectorActivity.this.gridView.getChildAt(a);
                    if (view instanceof PhotoAttachPhotoCell) {
                        PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                        cell.showCheck(true);
                    }
                }
                if (!ImagePreSelectorActivity.selectedPhotosOrder.isEmpty() && !ImagePreSelectorActivity.selectedPhotos.isEmpty()) {
                    Object object = ImagePreSelectorActivity.selectedPhotos.get(ImagePreSelectorActivity.selectedPhotosOrder.get(0));
                    if (object instanceof MediaController.PhotoEntry) {
                        MediaController.PhotoEntry checkData = (MediaController.PhotoEntry) object;
                        if (checkData.path.endsWith(".gif")) {
                            ImagePreSelectorActivity.this.currentSelectMediaType = 3;
                        } else if (checkData.isVideo) {
                            ImagePreSelectorActivity.this.currentSelectMediaType = 2;
                        } else {
                            ImagePreSelectorActivity.this.currentSelectMediaType = 1;
                        }
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
            public boolean cancelButtonPressed() {
                return false;
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
            public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
                MediaController.PhotoEntry photoEntry = ImagePreSelectorActivity.this.getPhotoEntryAtPosition(index);
                if (photoEntry != null) {
                    photoEntry.editedInfo = videoEditedInfo;
                }
                if (ImagePreSelectorActivity.selectedPhotos.isEmpty() && photoEntry != null) {
                    ImagePreSelectorActivity.this.addToSelectedPhotos(photoEntry, -1);
                }
                ImagePreSelectorActivity.this.applyCaption();
                ImagePreSelectorActivity.this.delegate.didPressedButton(7, true, notify, scheduleDate);
            }
        };
        this.openInterpolator = new OvershootInterpolator(0.7f);
        this.mActivity = activity;
        setDelegate(this);
        checkCamera(false);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.albumsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.reloadInlineHints);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.cameraInitied);
        this.mblnCanScroll = false;
        this.cameraDrawable = activity.getResources().getDrawable(R.drawable.instant_camera).mutate();
        AnonymousClass2 anonymousClass2 = new AnonymousClass2(activity);
        this.sizeNotifierFrameLayout = anonymousClass2;
        this.containerView = anonymousClass2;
        this.containerView.setWillNotDraw(false);
        this.containerView.setPadding(this.backgroundPaddingLeft, 0, this.backgroundPaddingLeft, 0);
        TextView textView = new TextView(activity);
        this.selectedTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.selectedTextView.setTextSize(1, 16.0f);
        this.selectedTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.selectedTextView.setGravity(51);
        this.selectedTextView.setVisibility(4);
        this.selectedTextView.setAlpha(0.0f);
        this.containerView.addView(this.selectedTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 23.0f, 0.0f, 48.0f, 0.0f));
        ActionBar actionBar = new ActionBar(activity) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.3
            @Override // android.view.View
            public void setAlpha(float alpha) {
                super.setAlpha(alpha);
                ImagePreSelectorActivity.this.containerView.invalidate();
            }
        };
        this.actionBar = actionBar;
        actionBar.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_dialogTextBlack), false);
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_dialogButtonSelector), false);
        this.actionBar.setTitleColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.actionBar.setOccupyStatusBar(false);
        this.actionBar.setAlpha(0.0f);
        this.containerView.addView(this.actionBar, LayoutHelper.createFrame(-1, -2.0f));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.4
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    ImagePreSelectorActivity.this.dismiss();
                    return;
                }
                if (id == 3) {
                    ImagePreSelectorActivity.this.delegate.didPressedButton(4, true, true, 0);
                    return;
                }
                if (id == 0) {
                    ImagePreSelectorActivity.this.applyCaption();
                    ImagePreSelectorActivity.this.delegate.didPressedButton(7, false, true, 0);
                    return;
                }
                if (id == 1) {
                    ImagePreSelectorActivity.this.applyCaption();
                    ImagePreSelectorActivity.this.delegate.didPressedButton(4, true, true, 0);
                } else if (id >= 10) {
                    ImagePreSelectorActivity imagePreSelectorActivity = ImagePreSelectorActivity.this;
                    imagePreSelectorActivity.selectedAlbumEntry = (MediaController.AlbumEntry) imagePreSelectorActivity.dropDownAlbums.get(id - 10);
                    if (ImagePreSelectorActivity.this.selectedAlbumEntry == ImagePreSelectorActivity.this.galleryAlbumEntry) {
                        ImagePreSelectorActivity.this.dropDown.setText(LocaleController.getString("AllMedia", R.string.AllMedia));
                    } else {
                        ImagePreSelectorActivity.this.dropDown.setText(ImagePreSelectorActivity.this.selectedAlbumEntry.bucketName);
                    }
                    ImagePreSelectorActivity.this.adapter.notifyDataSetChanged();
                    ImagePreSelectorActivity.this.cameraAttachAdapter.notifyDataSetChanged();
                    ImagePreSelectorActivity.this.layoutManager.scrollToPositionWithOffset(0, (-ImagePreSelectorActivity.this.gridView.getPaddingTop()) + AndroidUtilities.dp(7.0f));
                }
            }
        });
        RecyclerListView recyclerListView = new RecyclerListView(activity) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.5
            @Override // android.view.View
            public void setTranslationY(float translationY) {
                super.setTranslationY(translationY);
                ImagePreSelectorActivity.this.containerView.invalidate();
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public boolean onTouchEvent(MotionEvent e) {
                if (e.getAction() == 0 && e.getY() < ImagePreSelectorActivity.this.scrollOffsetY - AndroidUtilities.dp(44.0f)) {
                    return false;
                }
                return super.onTouchEvent(e);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent e) {
                if (e.getAction() == 0 && e.getY() < ImagePreSelectorActivity.this.scrollOffsetY - AndroidUtilities.dp(44.0f)) {
                    return false;
                }
                return super.onInterceptTouchEvent(e);
            }
        };
        this.gridView = recyclerListView;
        PhotoAttachAdapter photoAttachAdapter = new PhotoAttachAdapter(activity, true);
        this.adapter = photoAttachAdapter;
        recyclerListView.setAdapter(photoAttachAdapter);
        this.gridView.setClipToPadding(false);
        this.gridView.setItemAnimator(null);
        this.gridView.setLayoutAnimation(null);
        this.gridView.setVerticalScrollBarEnabled(false);
        this.gridView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        this.gridView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.containerView.addView(this.gridView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 11.0f, 0.0f, 0.0f));
        this.gridView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.6
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                if (ImagePreSelectorActivity.this.gridView.getChildCount() > 0) {
                    ImagePreSelectorActivity.this.updateLayout(true);
                    ImagePreSelectorActivity.this.checkCameraViewPosition();
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                RecyclerListView.Holder holder;
                if (newState == 0) {
                    int offset = AndroidUtilities.dp(13.0f);
                    int top = (ImagePreSelectorActivity.this.scrollOffsetY - ImagePreSelectorActivity.this.backgroundPaddingTop) - offset;
                    if (ImagePreSelectorActivity.this.backgroundPaddingTop + top < ActionBar.getCurrentActionBarHeight() && (holder = (RecyclerListView.Holder) ImagePreSelectorActivity.this.gridView.findViewHolderForAdapterPosition(0)) != null && holder.itemView.getTop() > AndroidUtilities.dp(7.0f)) {
                        ImagePreSelectorActivity.this.gridView.smoothScrollBy(0, holder.itemView.getTop() - AndroidUtilities.dp(7.0f));
                    }
                }
            }
        });
        GridLayoutManager gridLayoutManager = new GridLayoutManager(activity, this.itemSize) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.7
            @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = gridLayoutManager;
        gridLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.8
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                if (position == ImagePreSelectorActivity.this.adapter.itemsCount - 1) {
                    return ImagePreSelectorActivity.this.layoutManager.getSpanCount();
                }
                return ImagePreSelectorActivity.this.itemSize + (position % ImagePreSelectorActivity.this.itemsPerRow != ImagePreSelectorActivity.this.itemsPerRow + (-1) ? AndroidUtilities.dp(5.0f) : 0);
            }
        });
        this.gridView.setLayoutManager(this.layoutManager);
        this.gridView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$Oioj_u0_6SRbIoqwvLOob5a5PQg
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i2) {
                this.f$0.lambda$new$0$ImagePreSelectorActivity(view, i2);
            }
        });
        this.gridView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$ZIusa0752IKozcxol2etrNebm0k
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i2) {
                return this.f$0.lambda$new$1$ImagePreSelectorActivity(view, i2);
            }
        });
        RecyclerViewItemRangeSelector recyclerViewItemRangeSelector = new RecyclerViewItemRangeSelector(new RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.9
            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public int getItemCount() {
                return ImagePreSelectorActivity.this.adapter.getItemCount();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public void setSelected(View view, int index, boolean selected) {
                if (selected != ImagePreSelectorActivity.this.shouldSelect || !(view instanceof PhotoAttachPhotoCell)) {
                    return;
                }
                PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                cell.callDelegate();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public boolean isSelected(int index) {
                MediaController.PhotoEntry entry = ImagePreSelectorActivity.this.adapter.getPhoto(index);
                return entry != null && ImagePreSelectorActivity.selectedPhotos.containsKey(Integer.valueOf(entry.imageId));
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public boolean isIndexSelectable(int index) {
                return ImagePreSelectorActivity.this.adapter.getItemViewType(index) == 0;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public void onStartStopSelection(boolean start) {
                ImagePreSelectorActivity.this.gridView.hideSelector();
            }
        });
        this.itemRangeSelector = recyclerViewItemRangeSelector;
        this.gridView.addOnItemTouchListener(recyclerViewItemRangeSelector);
        ActionBarMenu actionBarMenuCreateMenu = this.actionBar.createMenu();
        ActionBarMenuItem actionBarMenuItemAddItem = actionBarMenuCreateMenu.addItem(3, LocaleController.getString("fc_skip", R.string.fc_skip));
        this.isSkipMenu = actionBarMenuItemAddItem;
        TextView textView2 = (TextView) actionBarMenuItemAddItem.getContentView();
        textView2.setTextColor(activity.getResources().getColor(R.color.color_FF2ECEFD));
        textView2.setTextSize(16.0f);
        ActionBarMenuItem actionBarMenuItem = new ActionBarMenuItem(activity, actionBarMenuCreateMenu, 0, 0);
        this.dropDownContainer = actionBarMenuItem;
        actionBarMenuItem.setSubMenuOpenSide(1);
        this.actionBar.addView(this.dropDownContainer, 0, LayoutHelper.createFrame(-2.0f, -1.0f, 17, AndroidUtilities.isTablet() ? 64.0f : 56.0f, 0.0f, 40.0f, 0.0f));
        this.dropDownContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$r9wkO6oGqjIzvWKqgjJ2P2uUn8E
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$2$ImagePreSelectorActivity(view);
            }
        });
        TextView textView3 = new TextView(activity);
        this.dropDown = textView3;
        textView3.setGravity(17);
        this.dropDown.setSingleLine(true);
        this.dropDown.setLines(1);
        this.dropDown.setMaxLines(1);
        this.dropDown.setEllipsize(TextUtils.TruncateAt.END);
        this.dropDown.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.dropDown.setTextSize(16.0f);
        this.dropDown.setText(LocaleController.getString("AllMedia", R.string.AllMedia));
        this.dropDown.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        Drawable drawableMutate = activity.getResources().getDrawable(R.drawable.ic_arrow_drop_down).mutate();
        this.dropDownDrawable = drawableMutate;
        drawableMutate.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogTextBlack), PorterDuff.Mode.MULTIPLY));
        this.dropDown.setCompoundDrawablePadding(AndroidUtilities.dp(7.0f));
        this.dropDown.setPadding(0, 0, 0, 0);
        this.dropDownContainer.addView(this.dropDown, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 0.0f, 0.0f, 0.0f, 0.0f));
        View view = new View(activity);
        this.actionBarShadow = view;
        view.setAlpha(0.0f);
        this.actionBarShadow.setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        this.containerView.addView(this.actionBarShadow, LayoutHelper.createFrame(-1, 1.0f));
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(activity);
        this.progressView = emptyTextProgressView;
        emptyTextProgressView.setText(LocaleController.getString("NoPhotos", R.string.NoPhotos));
        this.progressView.setOnTouchListener(null);
        this.progressView.setTextSize(20);
        this.containerView.addView(this.progressView, LayoutHelper.createFrame(-1, 80.0f));
        if (this.loading) {
            this.progressView.showProgress();
        } else {
            this.progressView.showTextView();
        }
        this.commentTextView = new AnonymousClass10(activity, this.sizeNotifierFrameLayout, null, 1);
        this.commentTextView.setFilters(new InputFilter[]{new InputFilter.LengthFilter(MessagesController.getInstance(UserConfig.selectedAccount).maxCaptionLength)});
        this.commentTextView.setHint(LocaleController.getString("AddCaption", R.string.AddCaption));
        this.commentTextView.onResume();
        EditTextBoldCursor editText = this.commentTextView.getEditText();
        editText.setMaxLines(1);
        editText.setSingleLine(true);
        FrameLayout frameLayout = new FrameLayout(activity);
        this.writeButtonContainer = frameLayout;
        frameLayout.setVisibility(0);
        this.writeButtonContainer.setContentDescription(LocaleController.getString("Send", R.string.Send));
        this.writeButtonContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$kdpgxkAEj1h4qfrbD1CcbITt5HQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$3$ImagePreSelectorActivity(view2);
            }
        });
        this.writeButton = new ImageView(activity);
        this.writeButtonDrawable = Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), Theme.getColor(Theme.key_dialogFloatingButton), Theme.getColor(Theme.key_dialogFloatingButtonPressed));
        if (Build.VERSION.SDK_INT < 21) {
            Drawable drawableMutate2 = activity.getResources().getDrawable(R.drawable.floating_shadow_profile).mutate();
            drawableMutate2.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
            CombinedDrawable combinedDrawable = new CombinedDrawable(drawableMutate2, this.writeButtonDrawable, 0, 0);
            combinedDrawable.setIconSize(AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
            this.writeButtonDrawable = combinedDrawable;
        }
        this.writeButton.setBackgroundDrawable(this.writeButtonDrawable);
        this.writeButton.setImageResource(R.drawable.attach_send);
        this.writeButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogFloatingIcon), PorterDuff.Mode.MULTIPLY));
        this.writeButton.setScaleType(ImageView.ScaleType.CENTER);
        if (Build.VERSION.SDK_INT >= 21) {
            this.writeButton.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.11
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view2, Outline outline) {
                    outline.setOval(0, 0, AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
                }
            });
        }
        this.writeButtonContainer.addView(this.writeButton, LayoutHelper.createFrame(Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, 51, Build.VERSION.SDK_INT >= 21 ? 2.0f : 0.0f, 0.0f, 0.0f, 0.0f));
        this.textPaint.setTextSize(AndroidUtilities.dp(12.0f));
        this.textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        TextView textView4 = new TextView(activity);
        this.recordTime = textView4;
        textView4.setBackgroundResource(R.drawable.system);
        this.recordTime.getBackground().setColorFilter(new PorterDuffColorFilter(1711276032, PorterDuff.Mode.MULTIPLY));
        this.recordTime.setTextSize(1, 15.0f);
        this.recordTime.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.recordTime.setAlpha(0.0f);
        this.recordTime.setTextColor(-1);
        this.recordTime.setPadding(AndroidUtilities.dp(10.0f), AndroidUtilities.dp(5.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(5.0f));
        this.container.addView(this.recordTime, LayoutHelper.createFrame(-2.0f, -2.0f, 49, 0.0f, AndroidUtilities.statusBarHeight, 0.0f, 0.0f));
        FrameLayout frameLayout2 = new FrameLayout(activity) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.12
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                int cx;
                int cy;
                int cx2;
                int cy2;
                int cy3;
                int cy22;
                if (getMeasuredWidth() == AndroidUtilities.dp(126.0f)) {
                    cx = getMeasuredWidth() / 2;
                    cy = getMeasuredHeight() / 2;
                    cy22 = getMeasuredWidth() / 2;
                    cx2 = cy22;
                    cy2 = (cy / 2) + cy + AndroidUtilities.dp(17.0f);
                    cy3 = (cy / 2) - AndroidUtilities.dp(17.0f);
                } else {
                    cx = getMeasuredWidth() / 2;
                    cy = (getMeasuredHeight() / 2) - AndroidUtilities.dp(13.0f);
                    cx2 = (cx / 2) + cx + AndroidUtilities.dp(17.0f);
                    int cx3 = (cx / 2) - AndroidUtilities.dp(17.0f);
                    cy2 = (getMeasuredHeight() / 2) - AndroidUtilities.dp(13.0f);
                    cy3 = cy2;
                    cy22 = cx3;
                }
                int cx32 = getMeasuredHeight();
                int y = (cx32 - ImagePreSelectorActivity.this.tooltipTextView.getMeasuredHeight()) - AndroidUtilities.dp(12.0f);
                if (getMeasuredWidth() == AndroidUtilities.dp(126.0f)) {
                    ImagePreSelectorActivity.this.tooltipTextView.layout(cx - (ImagePreSelectorActivity.this.tooltipTextView.getMeasuredWidth() / 2), getMeasuredHeight(), (ImagePreSelectorActivity.this.tooltipTextView.getMeasuredWidth() / 2) + cx, getMeasuredHeight() + ImagePreSelectorActivity.this.tooltipTextView.getMeasuredHeight());
                } else {
                    ImagePreSelectorActivity.this.tooltipTextView.layout(cx - (ImagePreSelectorActivity.this.tooltipTextView.getMeasuredWidth() / 2), y, (ImagePreSelectorActivity.this.tooltipTextView.getMeasuredWidth() / 2) + cx, ImagePreSelectorActivity.this.tooltipTextView.getMeasuredHeight() + y);
                }
                ImagePreSelectorActivity.this.shutterButton.layout(cx - (ImagePreSelectorActivity.this.shutterButton.getMeasuredWidth() / 2), cy - (ImagePreSelectorActivity.this.shutterButton.getMeasuredHeight() / 2), (ImagePreSelectorActivity.this.shutterButton.getMeasuredWidth() / 2) + cx, (ImagePreSelectorActivity.this.shutterButton.getMeasuredHeight() / 2) + cy);
                ImagePreSelectorActivity.this.switchCameraButton.layout(cx2 - (ImagePreSelectorActivity.this.switchCameraButton.getMeasuredWidth() / 2), cy2 - (ImagePreSelectorActivity.this.switchCameraButton.getMeasuredHeight() / 2), (ImagePreSelectorActivity.this.switchCameraButton.getMeasuredWidth() / 2) + cx2, (ImagePreSelectorActivity.this.switchCameraButton.getMeasuredHeight() / 2) + cy2);
                for (int a = 0; a < 2; a++) {
                    ImagePreSelectorActivity.this.flashModeButton[a].layout(cy22 - (ImagePreSelectorActivity.this.flashModeButton[a].getMeasuredWidth() / 2), cy3 - (ImagePreSelectorActivity.this.flashModeButton[a].getMeasuredHeight() / 2), (ImagePreSelectorActivity.this.flashModeButton[a].getMeasuredWidth() / 2) + cy22, (ImagePreSelectorActivity.this.flashModeButton[a].getMeasuredHeight() / 2) + cy3);
                }
            }
        };
        this.cameraPanel = frameLayout2;
        frameLayout2.setVisibility(8);
        this.cameraPanel.setAlpha(0.0f);
        this.container.addView(this.cameraPanel, LayoutHelper.createFrame(-1, 126, 83));
        TextView textView5 = new TextView(activity);
        this.counterTextView = textView5;
        textView5.setBackgroundResource(R.drawable.photos_rounded);
        this.counterTextView.setVisibility(8);
        this.counterTextView.setTextColor(-1);
        this.counterTextView.setGravity(17);
        this.counterTextView.setPivotX(0.0f);
        this.counterTextView.setPivotY(0.0f);
        this.counterTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.counterTextView.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.photos_arrow, 0);
        this.counterTextView.setCompoundDrawablePadding(AndroidUtilities.dp(4.0f));
        this.counterTextView.setPadding(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(16.0f), 0);
        this.container.addView(this.counterTextView, LayoutHelper.createFrame(-2.0f, 38.0f, 51, 0.0f, 0.0f, 0.0f, 116.0f));
        this.counterTextView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$57uTaylyOlYPtkNN2WWMPNp2Ipw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$4$ImagePreSelectorActivity(view2);
            }
        });
        ZoomControlView zoomControlView = new ZoomControlView(activity);
        this.zoomControlView = zoomControlView;
        zoomControlView.setVisibility(8);
        this.zoomControlView.setAlpha(0.0f);
        this.container.addView(this.zoomControlView, LayoutHelper.createFrame(-2.0f, 50.0f, 51, 0.0f, 0.0f, 0.0f, 116.0f));
        this.zoomControlView.setDelegate(new ZoomControlView.ZoomControlViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$o_5JEIQyrpEe-2XiqkmENk67lLE
            @Override // im.uwrkaxlmjj.ui.components.ZoomControlView.ZoomControlViewDelegate
            public final void didSetZoom(float f) {
                this.f$0.lambda$new$5$ImagePreSelectorActivity(f);
            }
        });
        ShutterButton shutterButton = new ShutterButton(activity);
        this.shutterButton = shutterButton;
        this.cameraPanel.addView(shutterButton, LayoutHelper.createFrame(84, 84, 17));
        this.shutterButton.setDelegate(new AnonymousClass13(activity));
        this.shutterButton.setFocusable(true);
        this.shutterButton.setContentDescription(LocaleController.getString("AccDescrShutter", R.string.AccDescrShutter));
        ImageView imageView = new ImageView(activity);
        this.switchCameraButton = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.cameraPanel.addView(this.switchCameraButton, LayoutHelper.createFrame(48, 48, 21));
        this.switchCameraButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$ZBsHY89kYcn1P2OeL-U3LBs3G7E
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$6$ImagePreSelectorActivity(view2);
            }
        });
        this.switchCameraButton.setContentDescription(LocaleController.getString("AccDescrSwitchCamera", R.string.AccDescrSwitchCamera));
        for (int i2 = 0; i2 < 2; i2++) {
            this.flashModeButton[i2] = new ImageView(activity);
            this.flashModeButton[i2].setScaleType(ImageView.ScaleType.CENTER);
            this.flashModeButton[i2].setVisibility(4);
            this.cameraPanel.addView(this.flashModeButton[i2], LayoutHelper.createFrame(48, 48, 51));
            this.flashModeButton[i2].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$-B8-BKYJtBL9Hi8DrP6tQdISxEk
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$new$7$ImagePreSelectorActivity(view2);
                }
            });
            this.flashModeButton[i2].setContentDescription("flash mode " + i2);
        }
        TextView textView6 = new TextView(activity);
        this.tooltipTextView = textView6;
        textView6.setTextSize(1, 15.0f);
        this.tooltipTextView.setTextColor(-1);
        this.tooltipTextView.setText(LocaleController.getString("TapForVideo", R.string.TapForVideo));
        this.tooltipTextView.setShadowLayer(AndroidUtilities.dp(3.33333f), 0.0f, AndroidUtilities.dp(0.666f), 1275068416);
        this.tooltipTextView.setPadding(AndroidUtilities.dp(6.0f), 0, AndroidUtilities.dp(6.0f), 0);
        this.cameraPanel.addView(this.tooltipTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 81, 0.0f, 0.0f, 0.0f, 16.0f));
        RecyclerListView recyclerListView2 = new RecyclerListView(activity) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.16
            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (ImagePreSelectorActivity.this.cameraPhotoRecyclerViewIgnoreLayout) {
                    return;
                }
                super.requestLayout();
            }
        };
        this.cameraPhotoRecyclerView = recyclerListView2;
        recyclerListView2.setVerticalScrollBarEnabled(true);
        RecyclerListView recyclerListView3 = this.cameraPhotoRecyclerView;
        PhotoAttachAdapter photoAttachAdapter2 = new PhotoAttachAdapter(activity, false);
        this.cameraAttachAdapter = photoAttachAdapter2;
        recyclerListView3.setAdapter(photoAttachAdapter2);
        this.cameraPhotoRecyclerView.setClipToPadding(false);
        this.cameraPhotoRecyclerView.setPadding(AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f), 0);
        this.cameraPhotoRecyclerView.setItemAnimator(null);
        this.cameraPhotoRecyclerView.setLayoutAnimation(null);
        this.cameraPhotoRecyclerView.setOverScrollMode(2);
        this.cameraPhotoRecyclerView.setVisibility(4);
        this.cameraPhotoRecyclerView.setAlpha(0.0f);
        this.container.addView(this.cameraPhotoRecyclerView, LayoutHelper.createFrame(-1, 80.0f));
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(activity, i, objArr == true ? 1 : 0) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.17
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.cameraPhotoLayoutManager = linearLayoutManager;
        this.cameraPhotoRecyclerView.setLayoutManager(linearLayoutManager);
        this.cameraPhotoRecyclerView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$D0PVb5aoPwfGfGlJFQv3YRI5dBY
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view2, int i3) {
                ImagePreSelectorActivity.lambda$new$8(view2, i3);
            }
        });
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity$2, reason: invalid class name */
    class AnonymousClass2 extends SizeNotifierFrameLayout {
        private boolean ignoreLayout;
        private float initialTranslationY;
        private int lastNotifyWidth;
        private RectF rect;

        AnonymousClass2(Context context) {
            super(context);
            this.rect = new RectF();
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            if (ImagePreSelectorActivity.this.cameraAnimationInProgress) {
                return true;
            }
            if (ImagePreSelectorActivity.this.cameraOpened) {
                return ImagePreSelectorActivity.this.processTouchEvent(ev);
            }
            if (ev.getAction() == 0 && ImagePreSelectorActivity.this.scrollOffsetY != 0 && ev.getY() < ImagePreSelectorActivity.this.scrollOffsetY - AndroidUtilities.dp(36.0f) && ImagePreSelectorActivity.this.actionBar.getAlpha() == 0.0f) {
                ImagePreSelectorActivity.this.dismiss();
                return true;
            }
            return super.onInterceptTouchEvent(ev);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            if (ImagePreSelectorActivity.this.cameraAnimationInProgress) {
                return true;
            }
            if (ImagePreSelectorActivity.this.cameraOpened) {
                return ImagePreSelectorActivity.this.processTouchEvent(event);
            }
            return !ImagePreSelectorActivity.this.isDismissed() && super.onTouchEvent(event);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int padding;
            int totalHeight = View.MeasureSpec.getSize(heightMeasureSpec);
            if (Build.VERSION.SDK_INT >= 21) {
                this.ignoreLayout = true;
                setPadding(ImagePreSelectorActivity.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight, ImagePreSelectorActivity.this.backgroundPaddingLeft, 0);
                this.ignoreLayout = false;
            }
            int availableHeight = totalHeight - getPaddingTop();
            int keyboardSize = getKeyboardHeight();
            float f = 20.0f;
            if (!AndroidUtilities.isInMultiwindow && keyboardSize <= AndroidUtilities.dp(20.0f)) {
                availableHeight -= ImagePreSelectorActivity.this.commentTextView.getEmojiPadding();
            }
            int availableWidth = View.MeasureSpec.getSize(widthMeasureSpec) - (ImagePreSelectorActivity.this.backgroundPaddingLeft * 2);
            if (!AndroidUtilities.isTablet() && AndroidUtilities.displaySize.x <= AndroidUtilities.displaySize.y) {
                ImagePreSelectorActivity.this.itemsPerRow = 3;
            } else {
                ImagePreSelectorActivity.this.itemsPerRow = 4;
            }
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) ImagePreSelectorActivity.this.gridView.getLayoutParams();
            layoutParams.topMargin = ActionBar.getCurrentActionBarHeight();
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) ImagePreSelectorActivity.this.actionBarShadow.getLayoutParams();
            layoutParams2.topMargin = ActionBar.getCurrentActionBarHeight();
            this.ignoreLayout = true;
            ImagePreSelectorActivity.this.itemSize = ((availableWidth - AndroidUtilities.dp(12.0f)) - AndroidUtilities.dp(10.0f)) / ImagePreSelectorActivity.this.itemsPerRow;
            if (ImagePreSelectorActivity.this.lastItemSize != ImagePreSelectorActivity.this.itemSize) {
                ImagePreSelectorActivity imagePreSelectorActivity = ImagePreSelectorActivity.this;
                imagePreSelectorActivity.lastItemSize = imagePreSelectorActivity.itemSize;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$2$5SUIlKeHiddrvpfiywYePfm-WBY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onMeasure$0$ImagePreSelectorActivity$2();
                    }
                });
            }
            TextView textView = ImagePreSelectorActivity.this.dropDown;
            if (!AndroidUtilities.isTablet() && AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y) {
                f = 18.0f;
            }
            textView.setTextSize(f);
            ImagePreSelectorActivity.this.layoutManager.setSpanCount((ImagePreSelectorActivity.this.itemSize * ImagePreSelectorActivity.this.itemsPerRow) + (AndroidUtilities.dp(5.0f) * (ImagePreSelectorActivity.this.itemsPerRow - 1)));
            int rows = (int) Math.ceil((ImagePreSelectorActivity.this.adapter.getItemCount() - 1) / ImagePreSelectorActivity.this.itemsPerRow);
            int contentSize = (ImagePreSelectorActivity.this.itemSize * rows) + ((rows - 1) * AndroidUtilities.dp(5.0f));
            int newSize = Math.max(0, ((availableHeight - contentSize) - ActionBar.getCurrentActionBarHeight()) - AndroidUtilities.dp(60.0f));
            if (ImagePreSelectorActivity.this.gridExtraSpace != newSize) {
                ImagePreSelectorActivity.this.gridExtraSpace = newSize;
                ImagePreSelectorActivity.this.adapter.notifyDataSetChanged();
            }
            if (!AndroidUtilities.isTablet() && AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y) {
                padding = availableHeight / 6;
            } else {
                int padding2 = availableHeight / 5;
                padding = padding2 * 2;
            }
            if (ImagePreSelectorActivity.this.gridView.getPaddingTop() != padding) {
                ImagePreSelectorActivity.this.gridView.setPadding(AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), AndroidUtilities.dp(48.0f));
            }
            this.ignoreLayout = false;
            onMeasureInternal(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(totalHeight, 1073741824));
        }

        public /* synthetic */ void lambda$onMeasure$0$ImagePreSelectorActivity$2() {
            ImagePreSelectorActivity.this.adapter.notifyDataSetChanged();
        }

        private void onMeasureInternal(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
            setMeasuredDimension(widthSize, heightSize);
            int widthSize2 = widthSize - (ImagePreSelectorActivity.this.backgroundPaddingLeft * 2);
            int keyboardSize = getKeyboardHeight();
            if (keyboardSize <= AndroidUtilities.dp(20.0f)) {
                if (!AndroidUtilities.isInMultiwindow) {
                    heightSize -= ImagePreSelectorActivity.this.commentTextView.getEmojiPadding();
                    heightMeasureSpec = View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824);
                }
            } else {
                this.ignoreLayout = true;
                ImagePreSelectorActivity.this.commentTextView.hideEmojiView();
                this.ignoreLayout = false;
            }
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                if (child != null && child.getVisibility() != 8) {
                    if (ImagePreSelectorActivity.this.commentTextView != null && ImagePreSelectorActivity.this.commentTextView.isPopupView(child)) {
                        if (AndroidUtilities.isInMultiwindow || AndroidUtilities.isTablet()) {
                            if (AndroidUtilities.isTablet()) {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize2, 1073741824), View.MeasureSpec.makeMeasureSpec(Math.min(AndroidUtilities.dp(AndroidUtilities.isTablet() ? 200.0f : 320.0f), (heightSize - AndroidUtilities.statusBarHeight) + getPaddingTop()), 1073741824));
                            } else {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize2, 1073741824), View.MeasureSpec.makeMeasureSpec((heightSize - AndroidUtilities.statusBarHeight) + getPaddingTop(), 1073741824));
                            }
                        } else {
                            child.measure(View.MeasureSpec.makeMeasureSpec(widthSize2, 1073741824), View.MeasureSpec.makeMeasureSpec(child.getLayoutParams().height, 1073741824));
                        }
                    } else {
                        measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            int childLeft;
            int childTop;
            if (this.lastNotifyWidth != r - l) {
                this.lastNotifyWidth = r - l;
                if (ImagePreSelectorActivity.this.adapter != null) {
                    ImagePreSelectorActivity.this.adapter.notifyDataSetChanged();
                }
            }
            int count = getChildCount();
            int paddingBottom = (getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow || AndroidUtilities.isTablet()) ? 0 : ImagePreSelectorActivity.this.commentTextView.getEmojiPadding();
            setBottomClip(paddingBottom);
            for (int i = 0; i < count; i++) {
                View child = getChildAt(i);
                if (child.getVisibility() != 8) {
                    FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) child.getLayoutParams();
                    int width = child.getMeasuredWidth();
                    int height = child.getMeasuredHeight();
                    int gravity = lp.gravity;
                    if (gravity == -1) {
                        gravity = 51;
                    }
                    int absoluteGravity = gravity & 7;
                    int verticalGravity = gravity & 112;
                    int i2 = absoluteGravity & 7;
                    if (i2 == 1) {
                        int childLeft2 = r - l;
                        childLeft = (((childLeft2 - width) / 2) + lp.leftMargin) - lp.rightMargin;
                    } else if (i2 == 5) {
                        int childLeft3 = r - l;
                        childLeft = (((childLeft3 - width) - lp.rightMargin) - getPaddingRight()) - ImagePreSelectorActivity.this.backgroundPaddingLeft;
                    } else {
                        childLeft = lp.leftMargin + getPaddingLeft();
                    }
                    if (verticalGravity == 16) {
                        int childTop2 = b - paddingBottom;
                        childTop = ((((childTop2 - t) - height) / 2) + lp.topMargin) - lp.bottomMargin;
                    } else if (verticalGravity == 48) {
                        int childTop3 = lp.topMargin;
                        childTop = childTop3 + getPaddingTop();
                    } else if (verticalGravity == 80) {
                        int childTop4 = b - paddingBottom;
                        childTop = ((childTop4 - t) - height) - lp.bottomMargin;
                    } else {
                        childTop = lp.topMargin;
                    }
                    if (ImagePreSelectorActivity.this.commentTextView != null && ImagePreSelectorActivity.this.commentTextView.isPopupView(child)) {
                        if (AndroidUtilities.isTablet()) {
                            childTop = getMeasuredHeight() - child.getMeasuredHeight();
                        } else {
                            childTop = (getMeasuredHeight() + getKeyboardHeight()) - child.getMeasuredHeight();
                        }
                    }
                    child.layout(childLeft, childTop, childLeft + width, childTop + height);
                }
            }
            notifyHeightChanged();
            ImagePreSelectorActivity.this.updateLayout(false);
            ImagePreSelectorActivity.this.checkCameraViewPosition();
        }

        @Override // android.view.View, android.view.ViewParent
        public void requestLayout() {
            if (this.ignoreLayout) {
                return;
            }
            super.requestLayout();
        }

        @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout, android.view.View
        protected void onDraw(Canvas canvas) {
            int offset = AndroidUtilities.dp(13.0f);
            int top = (ImagePreSelectorActivity.this.scrollOffsetY - ImagePreSelectorActivity.this.backgroundPaddingTop) - offset;
            if (ImagePreSelectorActivity.this.currentSheetAnimationType == 1) {
                top = (int) (top + ImagePreSelectorActivity.this.gridView.getTranslationY());
            }
            int y = AndroidUtilities.dp(20.0f) + top;
            int height = getMeasuredHeight() + AndroidUtilities.dp(15.0f) + ImagePreSelectorActivity.this.backgroundPaddingTop;
            float rad = 1.0f;
            if (ImagePreSelectorActivity.this.backgroundPaddingTop + top < ActionBar.getCurrentActionBarHeight()) {
                float toMove = AndroidUtilities.dp(4.0f) + offset;
                float moveProgress = Math.min(1.0f, ((ActionBar.getCurrentActionBarHeight() - top) - ImagePreSelectorActivity.this.backgroundPaddingTop) / toMove);
                float availableToMove = ActionBar.getCurrentActionBarHeight() - toMove;
                int diff = (int) (availableToMove * moveProgress);
                top -= diff;
                y -= diff;
                height += diff;
                rad = 1.0f - moveProgress;
            }
            if (Build.VERSION.SDK_INT >= 21) {
                top += AndroidUtilities.statusBarHeight;
                y += AndroidUtilities.statusBarHeight;
                height -= AndroidUtilities.statusBarHeight;
            }
            ImagePreSelectorActivity.this.shadowDrawable.setBounds(0, top, getMeasuredWidth(), height);
            ImagePreSelectorActivity.this.shadowDrawable.draw(canvas);
            if (rad != 1.0f) {
                Theme.dialogs_onlineCirclePaint.setColor(Theme.getColor(Theme.key_dialogBackground));
                this.rect.set(ImagePreSelectorActivity.this.backgroundPaddingLeft, ImagePreSelectorActivity.this.backgroundPaddingTop + top, getMeasuredWidth() - ImagePreSelectorActivity.this.backgroundPaddingLeft, ImagePreSelectorActivity.this.backgroundPaddingTop + top + AndroidUtilities.dp(24.0f));
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(12.0f) * rad, AndroidUtilities.dp(12.0f) * rad, Theme.dialogs_onlineCirclePaint);
            }
            if (rad != 0.0f) {
                int w = AndroidUtilities.dp(36.0f);
                this.rect.set((getMeasuredWidth() - w) / 2, y, (getMeasuredWidth() + w) / 2, AndroidUtilities.dp(4.0f) + y);
                int color = Theme.getColor(Theme.key_sheet_scrollUp);
                int alpha = Color.alpha(color);
                Theme.dialogs_onlineCirclePaint.setColor(color);
                Theme.dialogs_onlineCirclePaint.setAlpha((int) (alpha * 1.0f * rad));
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), Theme.dialogs_onlineCirclePaint);
            }
            int color1 = Theme.getColor(Theme.key_dialogBackground);
            Theme.dialogs_onlineCirclePaint.setColor(color1);
            canvas.drawRect(ImagePreSelectorActivity.this.backgroundPaddingLeft, 0.0f, getMeasuredWidth() - ImagePreSelectorActivity.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight, Theme.dialogs_onlineCirclePaint);
        }

        @Override // android.view.View
        public void setTranslationY(float translationY) {
            if (ImagePreSelectorActivity.this.currentSheetAnimationType == 0) {
                this.initialTranslationY = translationY;
            }
            if (ImagePreSelectorActivity.this.currentSheetAnimationType == 1) {
                if (translationY < 0.0f) {
                    ImagePreSelectorActivity.this.gridView.setTranslationY(translationY);
                    float scale = (translationY / 40.0f) * (-0.1f);
                    int N = ImagePreSelectorActivity.this.gridView.getChildCount();
                    for (int a = 0; a < N; a++) {
                        View child = ImagePreSelectorActivity.this.gridView.getChildAt(a);
                        if (child instanceof PhotoAttachCameraCell) {
                            PhotoAttachCameraCell cell = (PhotoAttachCameraCell) child;
                            cell.getImageView().setScaleX(scale + 1.0f);
                            cell.getImageView().setScaleY(1.0f + scale);
                        } else if (child instanceof PhotoAttachPhotoCell) {
                            PhotoAttachPhotoCell cell2 = (PhotoAttachPhotoCell) child;
                            cell2.getCheckBox().setScaleX(scale + 1.0f);
                            cell2.getCheckBox().setScaleY(1.0f + scale);
                        }
                    }
                    translationY = 0.0f;
                } else {
                    ImagePreSelectorActivity.this.gridView.setTranslationY(0.0f);
                }
            }
            super.setTranslationY(translationY);
            ImagePreSelectorActivity.this.checkCameraViewPosition();
        }
    }

    public /* synthetic */ void lambda$new$0$ImagePreSelectorActivity(View view, int position) {
        if (!this.mediaEnabled || this.mActivity == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 23) {
            if (position == 0 && this.noCameraPermissions) {
                try {
                    this.mActivity.requestPermissions(new String[]{"android.permission.CAMERA"}, 18);
                    return;
                } catch (Exception e) {
                    return;
                }
            } else if (this.noGalleryPermissions) {
                try {
                    this.mActivity.requestPermissions(new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 4);
                    return;
                } catch (Exception e2) {
                    return;
                }
            }
        }
        if (position != 0 || this.selectedAlbumEntry != this.galleryAlbumEntry) {
            if (this.selectedAlbumEntry == this.galleryAlbumEntry) {
                position--;
            }
            ArrayList<Object> arrayList = getAllPhotosArray();
            if (position < 0 || position >= arrayList.size()) {
                return;
            }
            MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) arrayList.get(position);
            if (selectedPhotos.isEmpty() && this.maxSelectedPhotos < 9 && this.currentSelectMediaType == 1 && photoEntry.path.endsWith(".gif")) {
                FcToastUtils.show((CharSequence) "不能同时选择图片跟Gif动图");
                return;
            }
            int i = this.currentSelectMediaType;
            if ((i != 1 && i != 3) || !((MediaController.PhotoEntry) arrayList.get(position)).isVideo) {
                if (this.currentSelectMediaType == 1 && ((MediaController.PhotoEntry) arrayList.get(position)).path.endsWith(".gif")) {
                    FcToastUtils.show((CharSequence) "不能同时选择图片跟Gif动图");
                    return;
                }
                if (this.currentSelectMediaType == 3 && !selectedPhotos.containsKey(Integer.valueOf(((MediaController.PhotoEntry) arrayList.get(position)).imageId))) {
                    if (((MediaController.PhotoEntry) arrayList.get(position)).path.endsWith(".gif")) {
                        FcToastUtils.show((CharSequence) "最多只能选择一张Gif动图");
                        return;
                    } else {
                        FcToastUtils.show((CharSequence) "不能同时选择图片跟Gif动图");
                        return;
                    }
                }
                ImagePreviewActivity.getInstance().setParentActivity(this.mActivity);
                ImagePreviewActivity.getInstance().setMaxSelectedPhotos(this.maxSelectedPhotos, this.allowOrder);
                ImagePreviewActivity.getInstance().setSelectPreviewMode(true);
                ImagePreviewActivity.getInstance().setCurrentSelectMediaType(true, this.currentSelectMediaType);
                ImagePreviewActivity.getInstance().openPhotoForSelect(arrayList, position, 0, this.photoViewerProvider, (ChatActivity) null);
                AndroidUtilities.hideKeyboard(this.mActivity.getCurrentFocus());
                return;
            }
            FcToastUtils.show((CharSequence) "不能同时选择图片跟视频");
            return;
        }
        if (SharedConfig.inappCamera) {
            if (this.maxSelectedPhotos >= 0 && selectedPhotos.size() >= this.maxSelectedPhotos) {
                XDialog.Builder builder = new XDialog.Builder(getContext());
                builder.setTitle(LocaleController.getString("image_select_tip", R.string.image_select_tip));
                builder.setMessage(LocaleController.formatString("image_select_max_warn", R.string.image_select_max_warn, Integer.valueOf(this.maxSelectedPhotos)));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                builder.show();
                return;
            }
            openCamera(true);
            return;
        }
        ChatAttachViewDelegate chatAttachViewDelegate = this.delegate;
        if (chatAttachViewDelegate != null) {
            chatAttachViewDelegate.didPressedButton(0, false, true, 0);
        }
    }

    public /* synthetic */ boolean lambda$new$1$ImagePreSelectorActivity(View view, int position) {
        if (position == 0 && this.selectedAlbumEntry == this.galleryAlbumEntry) {
            ChatAttachViewDelegate chatAttachViewDelegate = this.delegate;
            if (chatAttachViewDelegate != null) {
                chatAttachViewDelegate.didPressedButton(0, false, true, 0);
            }
            return true;
        }
        if (view instanceof PhotoAttachPhotoCell) {
            PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
            RecyclerViewItemRangeSelector recyclerViewItemRangeSelector = this.itemRangeSelector;
            boolean z = !cell.isChecked();
            this.shouldSelect = z;
            recyclerViewItemRangeSelector.setIsActive(view, true, position, z);
        }
        return false;
    }

    public /* synthetic */ void lambda$new$2$ImagePreSelectorActivity(View view) {
        this.dropDownContainer.toggleSubMenu();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity$10, reason: invalid class name */
    class AnonymousClass10 extends EditTextEmoji {
        AnonymousClass10(Context context, SizeNotifierFrameLayout parent, BaseFragment fragment, int style) {
            super(context, parent, fragment, style);
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            if (!ImagePreSelectorActivity.this.enterCommentEventSent) {
                ImagePreSelectorActivity.this.delegate.needEnterComment();
                ImagePreSelectorActivity.this.setFocusable(true);
                ImagePreSelectorActivity.this.enterCommentEventSent = true;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$10$Y3XWOKsL3xKDFgqbyIA3P8qKfpw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onInterceptTouchEvent$0$ImagePreSelectorActivity$10();
                    }
                });
            }
            return super.onInterceptTouchEvent(ev);
        }

        public /* synthetic */ void lambda$onInterceptTouchEvent$0$ImagePreSelectorActivity$10() {
            ImagePreSelectorActivity.this.commentTextView.openKeyboard();
        }
    }

    public /* synthetic */ void lambda$new$3$ImagePreSelectorActivity(View v) {
        sendPressed(true, 0);
    }

    public /* synthetic */ void lambda$new$4$ImagePreSelectorActivity(View v) {
        if (this.cameraView == null) {
            return;
        }
        openPhotoViewer(null, false, false);
        CameraController.getInstance().stopPreview(this.cameraView.getCameraSession());
    }

    public /* synthetic */ void lambda$new$5$ImagePreSelectorActivity(float zoom) {
        CameraView cameraView = this.cameraView;
        if (cameraView != null) {
            this.cameraZoom = zoom;
            cameraView.setZoom(zoom);
        }
        showZoomControls(true, true);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity$13, reason: invalid class name */
    class AnonymousClass13 implements ShutterButton.ShutterButtonDelegate {
        private File outputFile;
        final /* synthetic */ Activity val$mActivity;
        private boolean zoomingWas;

        AnonymousClass13(Activity activity) {
            this.val$mActivity = activity;
        }

        @Override // im.uwrkaxlmjj.ui.components.ShutterButton.ShutterButtonDelegate
        public boolean shutterLongPressed() {
            if (ImagePreSelectorActivity.this.mediaCaptured || ImagePreSelectorActivity.this.takingPhoto || ImagePreSelectorActivity.this.mActivity == null || ImagePreSelectorActivity.this.cameraView == null) {
                return false;
            }
            if (Build.VERSION.SDK_INT >= 23 && ImagePreSelectorActivity.this.mActivity.checkSelfPermission("android.permission.RECORD_AUDIO") != 0) {
                ImagePreSelectorActivity.this.requestingPermissions = true;
                ImagePreSelectorActivity.this.mActivity.requestPermissions(new String[]{"android.permission.RECORD_AUDIO"}, 21);
                return false;
            }
            for (int a = 0; a < 2; a++) {
                ImagePreSelectorActivity.this.flashModeButton[a].setAlpha(0.0f);
            }
            ImagePreSelectorActivity.this.switchCameraButton.setAlpha(0.0f);
            ImagePreSelectorActivity.this.tooltipTextView.setAlpha(0.0f);
            this.outputFile = AndroidUtilities.generateVideoPath(false);
            ImagePreSelectorActivity.this.recordTime.setAlpha(1.0f);
            ImagePreSelectorActivity.this.recordTime.setText(LocaleController.getString("friendscircle_publish_remain", R.string.friendscircle_publish_remain) + LocaleController.formatString("SlowmodeSeconds", R.string.SlowmodeSeconds, 59));
            ImagePreSelectorActivity.this.videoRecordTime = 0;
            ImagePreSelectorActivity.this.videoRecordRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$13$9bfU1PoxKmW2I_5sG6b6oxPjMtM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$shutterLongPressed$0$ImagePreSelectorActivity$13();
                }
            };
            AndroidUtilities.lockOrientation(this.val$mActivity);
            CameraController.getInstance().recordVideo(ImagePreSelectorActivity.this.cameraView.getCameraSession(), this.outputFile, new CameraController.VideoTakeCallback() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$13$cGltF1axcOJppfBH-rxEFNb5wBU
                @Override // im.uwrkaxlmjj.messenger.camera.CameraController.VideoTakeCallback
                public final void onFinishVideoRecording(String str, long j) {
                    this.f$0.lambda$shutterLongPressed$1$ImagePreSelectorActivity$13(str, j);
                }
            }, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$13$qCXn5SLvsHxr0CX1swqgndjXevU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$shutterLongPressed$2$ImagePreSelectorActivity$13();
                }
            });
            ImagePreSelectorActivity.this.shutterButton.setState(ShutterButton.State.RECORDING, true);
            return true;
        }

        public /* synthetic */ void lambda$shutterLongPressed$0$ImagePreSelectorActivity$13() {
            if (ImagePreSelectorActivity.this.videoRecordRunnable == null) {
                return;
            }
            ImagePreSelectorActivity.access$7108(ImagePreSelectorActivity.this);
            ImagePreSelectorActivity.this.recordTime.setText(LocaleController.getString("friendscircle_publish_remain", R.string.friendscircle_publish_remain) + LocaleController.formatString("SlowmodeSeconds", R.string.SlowmodeSeconds, Integer.valueOf(59 - ImagePreSelectorActivity.this.videoRecordTime)));
            if (ImagePreSelectorActivity.this.videoRecordTime == 59) {
                ImagePreSelectorActivity.this.stopRecord();
            }
            AndroidUtilities.runOnUIThread(ImagePreSelectorActivity.this.videoRecordRunnable, 1000L);
        }

        public /* synthetic */ void lambda$shutterLongPressed$1$ImagePreSelectorActivity$13(String thumbPath, long duration) {
            if (this.outputFile != null && ImagePreSelectorActivity.this.mActivity != null) {
                boolean unused = ImagePreSelectorActivity.mediaFromExternalCamera = false;
                MediaController.PhotoEntry photoEntry = new MediaController.PhotoEntry(0, ImagePreSelectorActivity.access$8010(), 0L, this.outputFile.getAbsolutePath(), 0, true);
                photoEntry.duration = (int) duration;
                photoEntry.thumbPath = thumbPath;
                ImagePreSelectorActivity.this.openPhotoViewer(photoEntry, false, false);
            }
        }

        public /* synthetic */ void lambda$shutterLongPressed$2$ImagePreSelectorActivity$13() {
            AndroidUtilities.runOnUIThread(ImagePreSelectorActivity.this.videoRecordRunnable, 1000L);
        }

        @Override // im.uwrkaxlmjj.ui.components.ShutterButton.ShutterButtonDelegate
        public void shutterCancel() {
            if (ImagePreSelectorActivity.this.mediaCaptured) {
                return;
            }
            File file = this.outputFile;
            if (file != null) {
                file.delete();
                this.outputFile = null;
            }
            ImagePreSelectorActivity.this.resetRecordState();
            CameraController.getInstance().stopVideoRecording(ImagePreSelectorActivity.this.cameraView.getCameraSession(), true);
        }

        @Override // im.uwrkaxlmjj.ui.components.ShutterButton.ShutterButtonDelegate
        public void shutterReleased() {
            ImagePreSelectorActivity.this.stopRecord();
        }

        @Override // im.uwrkaxlmjj.ui.components.ShutterButton.ShutterButtonDelegate
        public boolean onTranslationChanged(float x, float y) {
            boolean isPortrait = ImagePreSelectorActivity.this.container.getWidth() < ImagePreSelectorActivity.this.container.getHeight();
            float val1 = isPortrait ? x : y;
            float val2 = isPortrait ? y : x;
            if (!this.zoomingWas && Math.abs(val1) > Math.abs(val2)) {
                return ImagePreSelectorActivity.this.zoomControlView.getTag() == null;
            }
            if (val2 < 0.0f) {
                ImagePreSelectorActivity.this.showZoomControls(true, true);
                ImagePreSelectorActivity.this.zoomControlView.setZoom((-val2) / AndroidUtilities.dp(200.0f), true);
                this.zoomingWas = true;
                return false;
            }
            if (this.zoomingWas) {
                ImagePreSelectorActivity.this.zoomControlView.setZoom(0.0f, true);
            }
            if (x == 0.0f && y == 0.0f) {
                this.zoomingWas = false;
            }
            if (this.zoomingWas) {
                return false;
            }
            return (x == 0.0f && y == 0.0f) ? false : true;
        }
    }

    public /* synthetic */ void lambda$new$6$ImagePreSelectorActivity(View v) {
        CameraView cameraView;
        if (this.takingPhoto || (cameraView = this.cameraView) == null || !cameraView.isInitied()) {
            return;
        }
        this.cameraView.switchCamera();
        ObjectAnimator animator = ObjectAnimator.ofFloat(this.switchCameraButton, (Property<ImageView, Float>) View.SCALE_X, 0.0f).setDuration(100L);
        animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.14
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator2) {
                ImagePreSelectorActivity.this.switchCameraButton.setImageResource((ImagePreSelectorActivity.this.cameraView == null || !ImagePreSelectorActivity.this.cameraView.isFrontface()) ? R.drawable.camera_revert2 : R.drawable.camera_revert1);
                ObjectAnimator.ofFloat(ImagePreSelectorActivity.this.switchCameraButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f).setDuration(100L).start();
            }
        });
        animator.start();
    }

    public /* synthetic */ void lambda$new$7$ImagePreSelectorActivity(final View currentImage) {
        CameraView cameraView;
        if (this.flashAnimationInProgress || (cameraView = this.cameraView) == null || !cameraView.isInitied() || !this.cameraOpened) {
            return;
        }
        String current = this.cameraView.getCameraSession().getCurrentFlashMode();
        String next = this.cameraView.getCameraSession().getNextFlashMode();
        if (current.equals(next)) {
            return;
        }
        this.cameraView.getCameraSession().setCurrentFlashMode(next);
        this.flashAnimationInProgress = true;
        ImageView[] imageViewArr = this.flashModeButton;
        final ImageView nextImage = imageViewArr[0] == currentImage ? imageViewArr[1] : imageViewArr[0];
        nextImage.setVisibility(0);
        setCameraFlashModeIcon(nextImage, next);
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(currentImage, (Property<View, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(48.0f)), ObjectAnimator.ofFloat(nextImage, (Property<ImageView, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f), 0.0f), ObjectAnimator.ofFloat(currentImage, (Property<View, Float>) View.ALPHA, 1.0f, 0.0f), ObjectAnimator.ofFloat(nextImage, (Property<ImageView, Float>) View.ALPHA, 0.0f, 1.0f));
        animatorSet.setDuration(200L);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.15
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                ImagePreSelectorActivity.this.flashAnimationInProgress = false;
                currentImage.setVisibility(4);
                nextImage.sendAccessibilityEvent(8);
            }
        });
        animatorSet.start();
    }

    static /* synthetic */ void lambda$new$8(View view, int position) {
        if (view instanceof PhotoAttachPhotoCell) {
            ((PhotoAttachPhotoCell) view).callDelegate();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void stopRecord() {
        CameraView cameraView;
        if (this.takingPhoto || (cameraView = this.cameraView) == null || this.mediaCaptured || cameraView.getCameraSession() == null) {
            return;
        }
        this.mediaCaptured = true;
        if (this.shutterButton.getState() == ShutterButton.State.RECORDING) {
            resetRecordState();
            CameraController.getInstance().stopVideoRecording(this.cameraView.getCameraSession(), false);
            this.shutterButton.setState(ShutterButton.State.DEFAULT, true);
        } else {
            final File cameraFile = AndroidUtilities.generatePicturePath(false);
            final boolean sameTakePictureOrientation = this.cameraView.getCameraSession().isSameTakePictureOrientation();
            this.cameraView.getCameraSession().setFlipFront(false);
            this.takingPhoto = CameraController.getInstance().takePicture(cameraFile, this.cameraView.getCameraSession(), new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$E9CeCbXkL7BuPsFSWQal7uGwIFI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$stopRecord$9$ImagePreSelectorActivity(cameraFile, sameTakePictureOrientation);
                }
            });
        }
    }

    public /* synthetic */ void lambda$stopRecord$9$ImagePreSelectorActivity(File cameraFile, boolean sameTakePictureOrientation) {
        this.takingPhoto = false;
        if (cameraFile == null || this.mActivity == null) {
            return;
        }
        int orientation = 0;
        try {
            ExifInterface ei = new ExifInterface(cameraFile.getAbsolutePath());
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
        mediaFromExternalCamera = false;
        int i = lastImageId;
        lastImageId = i - 1;
        MediaController.PhotoEntry photoEntry = new MediaController.PhotoEntry(0, i, 0L, cameraFile.getAbsolutePath(), orientation, false);
        photoEntry.canDeleteAfter = true;
        openPhotoViewer(photoEntry, sameTakePictureOrientation, false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog
    public void show() {
        super.show();
        this.buttonPressed = false;
    }

    public void setEditingMessageObject(MessageObject messageObject) {
        if (this.editingMessageObject == messageObject) {
            return;
        }
        this.editingMessageObject = messageObject;
        if (messageObject != null) {
            this.maxSelectedPhotos = 1;
            this.allowOrder = false;
        } else {
            this.maxSelectedPhotos = -1;
            this.allowOrder = true;
        }
    }

    public MessageObject getEditingMessageObject() {
        return this.editingMessageObject;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void applyCaption() {
        if (this.commentTextView.length() <= 0) {
            return;
        }
        int imageId = ((Integer) selectedPhotosOrder.get(0)).intValue();
        Object entry = selectedPhotos.get(Integer.valueOf(imageId));
        if (entry instanceof MediaController.PhotoEntry) {
            MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) entry;
            photoEntry.caption = this.commentTextView.getText().toString();
        } else if (entry instanceof MediaController.SearchImage) {
            MediaController.SearchImage searchImage = (MediaController.SearchImage) entry;
            searchImage.caption = this.commentTextView.getText().toString();
        }
    }

    private void sendPressed(boolean notify, int scheduleDate) {
        if (this.buttonPressed) {
            return;
        }
        applyCaption();
        this.buttonPressed = true;
        this.delegate.didPressedButton(7, true, notify, scheduleDate);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updatePhotosCounter(boolean added) {
        if (this.counterTextView == null) {
            return;
        }
        boolean hasVideo = false;
        boolean hasPhotos = false;
        for (Map.Entry<Object, Object> entry : selectedPhotos.entrySet()) {
            MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) entry.getValue();
            if (photoEntry.isVideo) {
                hasVideo = true;
            } else {
                hasPhotos = true;
            }
            if (hasVideo && hasPhotos) {
                break;
            }
        }
        int newSelectedCount = Math.max(1, selectedPhotos.size());
        if (hasVideo && hasPhotos) {
            this.counterTextView.setText(LocaleController.formatPluralString("Media", selectedPhotos.size()).toUpperCase());
            if (newSelectedCount != this.currentSelectedCount || added) {
                this.selectedTextView.setText(LocaleController.formatPluralString("MediaSelected", newSelectedCount));
            }
        } else if (hasVideo) {
            this.counterTextView.setText(LocaleController.formatPluralString("Videos", selectedPhotos.size()).toUpperCase());
            if (newSelectedCount != this.currentSelectedCount || added) {
                this.selectedTextView.setText(LocaleController.formatPluralString("VideosSelected", newSelectedCount));
            }
        } else {
            this.counterTextView.setText(LocaleController.formatPluralString("Photos", selectedPhotos.size()).toUpperCase());
            if (newSelectedCount != this.currentSelectedCount || added) {
                this.selectedTextView.setText(LocaleController.formatPluralString("PhotosSelected", newSelectedCount));
            }
        }
        this.currentSelectedCount = newSelectedCount;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean onCustomOpenAnimation() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openPhotoViewer(MediaController.PhotoEntry entry, boolean sameTakePictureOrientation, boolean external) {
        if (entry != null) {
            cameraPhotos.add(entry);
            selectedPhotos.put(Integer.valueOf(entry.imageId), entry);
            selectedPhotosOrder.add(Integer.valueOf(entry.imageId));
            updatePhotosButton();
            this.adapter.notifyDataSetChanged();
            this.cameraAttachAdapter.notifyDataSetChanged();
        }
        if (entry != null && !external && cameraPhotos.size() > 1) {
            updatePhotosCounter(false);
            if (this.cameraView != null) {
                this.zoomControlView.setZoom(0.0f, false);
                this.cameraZoom = 0.0f;
                this.cameraView.setZoom(0.0f);
                CameraController.getInstance().startPreview(this.cameraView.getCameraSession());
            }
            this.mediaCaptured = false;
            return;
        }
        if (cameraPhotos.isEmpty()) {
            return;
        }
        this.cancelTakingPhotos = true;
        ImagePreviewActivity.getInstance().setParentActivity(this.mActivity);
        ImagePreviewActivity.getInstance().setMaxSelectedPhotos(this.maxSelectedPhotos, this.allowOrder);
        ImagePreviewActivity.getInstance().setSelectPreviewMode(true);
        ImagePreviewActivity.getInstance().setCurrentSelectMediaType(true, this.currentSelectMediaType);
        ImagePreviewActivity.getInstance().openPhotoForSelect(getAllPhotosArray(), cameraPhotos.size() - 1, 5, new AnonymousClass18(sameTakePictureOrientation), (ChatActivity) null);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity$18, reason: invalid class name */
    class AnonymousClass18 extends BasePhotoProvider {
        final /* synthetic */ boolean val$sameTakePictureOrientation;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        AnonymousClass18(boolean z) {
            super();
            this.val$sameTakePictureOrientation = z;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public ImageReceiver.BitmapHolder getThumbForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean cancelButtonPressed() {
            if (ImagePreSelectorActivity.this.cameraOpened && ImagePreSelectorActivity.this.cameraView != null) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$18$IHcdYDHVu4OvKmmjecFh3TYaFNg
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$cancelButtonPressed$0$ImagePreSelectorActivity$18();
                    }
                }, 1000L);
                ImagePreSelectorActivity.this.zoomControlView.setZoom(0.0f, false);
                ImagePreSelectorActivity.this.cameraZoom = 0.0f;
                ImagePreSelectorActivity.this.cameraView.setZoom(0.0f);
                CameraController.getInstance().startPreview(ImagePreSelectorActivity.this.cameraView.getCameraSession());
            }
            if (ImagePreSelectorActivity.this.cancelTakingPhotos && ImagePreSelectorActivity.cameraPhotos.size() == 1) {
                int size = ImagePreSelectorActivity.cameraPhotos.size();
                for (int a = 0; a < size; a++) {
                    MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) ImagePreSelectorActivity.cameraPhotos.get(a);
                    new File(photoEntry.path).delete();
                    if (photoEntry.imagePath != null) {
                        new File(photoEntry.imagePath).delete();
                    }
                    if (photoEntry.thumbPath != null) {
                        new File(photoEntry.thumbPath).delete();
                    }
                }
                ImagePreSelectorActivity.cameraPhotos.clear();
                ImagePreSelectorActivity.selectedPhotosOrder.clear();
                ImagePreSelectorActivity.selectedPhotos.clear();
                ImagePreSelectorActivity.this.counterTextView.setVisibility(4);
                ImagePreSelectorActivity.this.cameraPhotoRecyclerView.setVisibility(8);
                ImagePreSelectorActivity.this.adapter.notifyDataSetChanged();
                ImagePreSelectorActivity.this.cameraAttachAdapter.notifyDataSetChanged();
                ImagePreSelectorActivity.this.updatePhotosButton();
            }
            return true;
        }

        public /* synthetic */ void lambda$cancelButtonPressed$0$ImagePreSelectorActivity$18() {
            if (ImagePreSelectorActivity.this.cameraView != null && !ImagePreSelectorActivity.this.isDismissed() && Build.VERSION.SDK_INT >= 21) {
                ImagePreSelectorActivity.this.cameraView.setSystemUiVisibility(1028);
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public void needAddMorePhotos() {
            ImagePreSelectorActivity.this.cancelTakingPhotos = false;
            if (ImagePreSelectorActivity.mediaFromExternalCamera) {
                ImagePreSelectorActivity.this.delegate.didPressedButton(0, true, true, 0);
                return;
            }
            if (!ImagePreSelectorActivity.this.cameraOpened) {
                ImagePreSelectorActivity.this.openCamera(false);
            }
            ImagePreSelectorActivity.this.counterTextView.setVisibility(0);
            ImagePreSelectorActivity.this.cameraPhotoRecyclerView.setVisibility(0);
            ImagePreSelectorActivity.this.counterTextView.setAlpha(1.0f);
            ImagePreSelectorActivity.this.updatePhotosCounter(false);
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
            if (!ImagePreSelectorActivity.cameraPhotos.isEmpty() && ImagePreSelectorActivity.this.mActivity != null) {
                if (videoEditedInfo != null && index >= 0 && index < ImagePreSelectorActivity.cameraPhotos.size()) {
                    MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) ImagePreSelectorActivity.cameraPhotos.get(index);
                    photoEntry.editedInfo = videoEditedInfo;
                    if (photoEntry.path.endsWith(".gif")) {
                        ImagePreSelectorActivity.this.currentSelectMediaType = 3;
                    } else if (photoEntry.isVideo) {
                        ImagePreSelectorActivity.this.currentSelectMediaType = 2;
                    } else {
                        ImagePreSelectorActivity.this.currentSelectMediaType = 1;
                    }
                }
                int size = ImagePreSelectorActivity.cameraPhotos.size();
                for (int a = 0; a < size; a++) {
                    AndroidUtilities.addMediaToGallery(((MediaController.PhotoEntry) ImagePreSelectorActivity.cameraPhotos.get(a)).path);
                }
                ImagePreSelectorActivity.this.applyCaption();
                ImagePreSelectorActivity.this.delegate.didPressedButton(8, true, notify, scheduleDate);
                ImagePreSelectorActivity.cameraPhotos.clear();
                ImagePreSelectorActivity.selectedPhotosOrder.clear();
                ImagePreSelectorActivity.selectedPhotos.clear();
                ImagePreSelectorActivity.this.adapter.notifyDataSetChanged();
                ImagePreSelectorActivity.this.cameraAttachAdapter.notifyDataSetChanged();
                ImagePreSelectorActivity.this.closeCamera(false);
                ImagePreSelectorActivity.this.dismiss();
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean scaleToFill() {
            if (ImagePreSelectorActivity.this.mActivity == null) {
                return false;
            }
            int locked = Settings.System.getInt(ImagePreSelectorActivity.this.mActivity.getContentResolver(), "accelerometer_rotation", 0);
            return this.val$sameTakePictureOrientation || locked == 1;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public void willHidePhotoViewer() {
            ImagePreSelectorActivity.this.mediaCaptured = false;
            int count = ImagePreSelectorActivity.this.gridView.getChildCount();
            for (int a = 0; a < count; a++) {
                View view = ImagePreSelectorActivity.this.gridView.getChildAt(a);
                if (view instanceof PhotoAttachPhotoCell) {
                    PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                    cell.showImage();
                    cell.showCheck(true);
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean canScrollAway() {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean canCaptureMorePhotos() {
            return ImagePreSelectorActivity.this.maxSelectedPhotos != 1;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showZoomControls(boolean show, boolean animated) {
        if ((this.zoomControlView.getTag() != null && show) || (this.zoomControlView.getTag() == null && !show)) {
            if (show) {
                Runnable runnable = this.zoomControlHideRunnable;
                if (runnable != null) {
                    AndroidUtilities.cancelRunOnUIThread(runnable);
                }
                Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$_FefbJmeOvXmc-6YXdvsaLxPOaM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$showZoomControls$10$ImagePreSelectorActivity();
                    }
                };
                this.zoomControlHideRunnable = runnable2;
                AndroidUtilities.runOnUIThread(runnable2, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                return;
            }
            return;
        }
        AnimatorSet animatorSet = this.zoomControlAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.zoomControlView.setTag(show ? 1 : null);
        AnimatorSet animatorSet2 = new AnimatorSet();
        this.zoomControlAnimation = animatorSet2;
        animatorSet2.setDuration(180L);
        AnimatorSet animatorSet3 = this.zoomControlAnimation;
        Animator[] animatorArr = new Animator[1];
        ZoomControlView zoomControlView = this.zoomControlView;
        Property property = View.ALPHA;
        float[] fArr = new float[1];
        fArr[0] = show ? 1.0f : 0.0f;
        animatorArr[0] = ObjectAnimator.ofFloat(zoomControlView, (Property<ZoomControlView, Float>) property, fArr);
        animatorSet3.playTogether(animatorArr);
        this.zoomControlAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.19
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                ImagePreSelectorActivity.this.zoomControlAnimation = null;
            }
        });
        this.zoomControlAnimation.start();
        if (show) {
            Runnable runnable3 = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$K0wPwW7HVcoOxXgas1V3hu9P9ho
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$showZoomControls$11$ImagePreSelectorActivity();
                }
            };
            this.zoomControlHideRunnable = runnable3;
            AndroidUtilities.runOnUIThread(runnable3, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }
    }

    public /* synthetic */ void lambda$showZoomControls$10$ImagePreSelectorActivity() {
        showZoomControls(false, true);
        this.zoomControlHideRunnable = null;
    }

    public /* synthetic */ void lambda$showZoomControls$11$ImagePreSelectorActivity() {
        showZoomControls(false, true);
        this.zoomControlHideRunnable = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean processTouchEvent(MotionEvent event) {
        CameraView cameraView;
        if (event == null) {
            return false;
        }
        if ((!this.pressed && event.getActionMasked() == 0) || event.getActionMasked() == 5) {
            this.zoomControlView.getHitRect(this.hitRect);
            if (this.zoomControlView.getTag() != null && this.hitRect.contains((int) event.getX(), (int) event.getY())) {
                return false;
            }
            if (!this.takingPhoto && !this.dragging) {
                if (event.getPointerCount() == 2) {
                    this.pinchStartDistance = (float) Math.hypot(event.getX(1) - event.getX(0), event.getY(1) - event.getY(0));
                    this.zooming = true;
                } else {
                    this.maybeStartDraging = true;
                    this.lastY = event.getY();
                    this.zooming = false;
                }
                this.zoomWas = false;
                this.pressed = true;
            }
        } else if (this.pressed) {
            if (event.getActionMasked() == 2) {
                if (this.zooming && event.getPointerCount() == 2 && !this.dragging) {
                    float newDistance = (float) Math.hypot(event.getX(1) - event.getX(0), event.getY(1) - event.getY(0));
                    if (this.zoomWas) {
                        float diff = (newDistance - this.pinchStartDistance) / AndroidUtilities.dp(100.0f);
                        this.pinchStartDistance = newDistance;
                        float f = this.cameraZoom + diff;
                        this.cameraZoom = f;
                        if (f < 0.0f) {
                            this.cameraZoom = 0.0f;
                        } else if (f > 1.0f) {
                            this.cameraZoom = 1.0f;
                        }
                        this.zoomControlView.setZoom(this.cameraZoom, false);
                        this.containerView.invalidate();
                        this.cameraView.setZoom(this.cameraZoom);
                        showZoomControls(true, true);
                    } else if (Math.abs(newDistance - this.pinchStartDistance) >= AndroidUtilities.getPixelsInCM(0.4f, false)) {
                        this.pinchStartDistance = newDistance;
                        this.zoomWas = true;
                    }
                } else {
                    float newY = event.getY();
                    float dy = newY - this.lastY;
                    if (this.maybeStartDraging) {
                        if (Math.abs(dy) > AndroidUtilities.getPixelsInCM(0.4f, false)) {
                            this.maybeStartDraging = false;
                            this.dragging = true;
                        }
                    } else if (this.dragging && (cameraView = this.cameraView) != null) {
                        cameraView.setTranslationY(cameraView.getTranslationY() + dy);
                        this.lastY = newY;
                        this.zoomControlView.setTag(null);
                        Runnable runnable = this.zoomControlHideRunnable;
                        if (runnable != null) {
                            AndroidUtilities.cancelRunOnUIThread(runnable);
                            this.zoomControlHideRunnable = null;
                        }
                        if (this.cameraPanel.getTag() == null) {
                            this.cameraPanel.setTag(1);
                            AnimatorSet animatorSet = new AnimatorSet();
                            animatorSet.playTogether(ObjectAnimator.ofFloat(this.cameraPanel, (Property<FrameLayout, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.zoomControlView, (Property<ZoomControlView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.counterTextView, (Property<TextView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.flashModeButton[0], (Property<ImageView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.flashModeButton[1], (Property<ImageView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.cameraPhotoRecyclerView, (Property<RecyclerListView, Float>) View.ALPHA, 0.0f));
                            animatorSet.setDuration(200L);
                            animatorSet.start();
                        }
                    }
                }
            } else if (event.getActionMasked() == 3 || event.getActionMasked() == 1 || event.getActionMasked() == 6) {
                this.pressed = false;
                this.zooming = false;
                if (0 != 0) {
                    this.zooming = false;
                } else if (this.dragging) {
                    this.dragging = false;
                    CameraView cameraView2 = this.cameraView;
                    if (cameraView2 != null) {
                        if (Math.abs(cameraView2.getTranslationY()) > this.cameraView.getMeasuredHeight() / 6.0f) {
                            closeCamera(true);
                        } else {
                            AnimatorSet animatorSet2 = new AnimatorSet();
                            animatorSet2.playTogether(ObjectAnimator.ofFloat(this.cameraView, (Property<CameraView, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(this.cameraPanel, (Property<FrameLayout, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.counterTextView, (Property<TextView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.flashModeButton[0], (Property<ImageView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.flashModeButton[1], (Property<ImageView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.cameraPhotoRecyclerView, (Property<RecyclerListView, Float>) View.ALPHA, 1.0f));
                            animatorSet2.setDuration(250L);
                            animatorSet2.setInterpolator(this.interpolator);
                            animatorSet2.start();
                            this.cameraPanel.setTag(null);
                        }
                    }
                } else {
                    CameraView cameraView3 = this.cameraView;
                    if (cameraView3 != null && !this.zoomWas) {
                        cameraView3.getLocationOnScreen(this.viewPosition);
                        float viewX = event.getRawX() - this.viewPosition[0];
                        float viewY = event.getRawY() - this.viewPosition[1];
                        this.cameraView.focusToPoint((int) viewX, (int) viewY);
                    }
                }
            }
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean onContainerTouchEvent(MotionEvent event) {
        return this.cameraOpened && processTouchEvent(event);
    }

    public void checkColors() {
        this.selectedTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.commentTextView.updateColors();
        Theme.setSelectorDrawableColor(this.writeButtonDrawable, Theme.getColor(Theme.key_dialogFloatingButton), false);
        Theme.setSelectorDrawableColor(this.writeButtonDrawable, Theme.getColor(Theme.key_dialogFloatingButtonPressed), true);
        this.writeButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogFloatingIcon), PorterDuff.Mode.MULTIPLY));
        this.dropDown.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.dropDownContainer.setPopupItemsColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem), false);
        this.dropDownContainer.setPopupItemsColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem), true);
        this.dropDownContainer.redrawPopup(Theme.getColor(Theme.key_actionBarDefaultSubmenuBackground));
        this.actionBarShadow.setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        this.progressView.setTextColor(Theme.getColor(Theme.key_emptyListPlaceholder));
        Theme.setDrawableColor(this.dropDownDrawable, Theme.getColor(Theme.key_dialogTextBlack));
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_dialogTextBlack), false);
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_dialogButtonSelector), false);
        this.actionBar.setTitleColor(Theme.getColor(Theme.key_dialogTextBlack));
        Theme.setDrawableColor(this.shadowDrawable, Theme.getColor(Theme.key_dialogBackground));
        Theme.setDrawableColor(this.cameraDrawable, Theme.getColor(Theme.key_dialogCameraIcon));
        FrameLayout frameLayout = this.cameraIcon;
        if (frameLayout != null) {
            frameLayout.invalidate();
        }
        this.gridView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        RecyclerView.ViewHolder holder = this.gridView.findViewHolderForAdapterPosition(0);
        if (holder != null && (holder.itemView instanceof PhotoAttachCameraCell)) {
            ((PhotoAttachCameraCell) holder.itemView).getImageView().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogCameraIcon), PorterDuff.Mode.MULTIPLY));
        }
        this.containerView.invalidate();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resetRecordState() {
        if (this.mActivity == null) {
            return;
        }
        for (int a = 0; a < 2; a++) {
            this.flashModeButton[a].setAlpha(1.0f);
        }
        this.switchCameraButton.setAlpha(1.0f);
        this.tooltipTextView.setAlpha(1.0f);
        this.recordTime.setAlpha(0.0f);
        AndroidUtilities.cancelRunOnUIThread(this.videoRecordRunnable);
        this.videoRecordRunnable = null;
        AndroidUtilities.unlockOrientation(this.mActivity);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0033  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void setCameraFlashModeIcon(android.widget.ImageView r5, java.lang.String r6) {
        /*
            r4 = this;
            int r0 = r6.hashCode()
            r1 = 3551(0xddf, float:4.976E-42)
            r2 = 2
            r3 = 1
            if (r0 == r1) goto L29
            r1 = 109935(0x1ad6f, float:1.54052E-40)
            if (r0 == r1) goto L1f
            r1 = 3005871(0x2dddaf, float:4.212122E-39)
            if (r0 == r1) goto L15
        L14:
            goto L33
        L15:
            java.lang.String r0 = "auto"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto L14
            r0 = 2
            goto L34
        L1f:
            java.lang.String r0 = "off"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto L14
            r0 = 0
            goto L34
        L29:
            java.lang.String r0 = "on"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto L14
            r0 = 1
            goto L34
        L33:
            r0 = -1
        L34:
            if (r0 == 0) goto L61
            if (r0 == r3) goto L4e
            if (r0 == r2) goto L3b
            goto L74
        L3b:
            r0 = 2131231010(0x7f080122, float:1.8078089E38)
            r5.setImageResource(r0)
            r0 = 2131689495(0x7f0f0017, float:1.9008007E38)
            java.lang.String r1 = "AccDescrCameraFlashAuto"
            java.lang.String r0 = im.uwrkaxlmjj.messenger.LocaleController.getString(r1, r0)
            r5.setContentDescription(r0)
            goto L74
        L4e:
            r0 = 2131231012(0x7f080124, float:1.8078093E38)
            r5.setImageResource(r0)
            r0 = 2131689497(0x7f0f0019, float:1.9008011E38)
            java.lang.String r1 = "AccDescrCameraFlashOn"
            java.lang.String r0 = im.uwrkaxlmjj.messenger.LocaleController.getString(r1, r0)
            r5.setContentDescription(r0)
            goto L74
        L61:
            r0 = 2131231011(0x7f080123, float:1.807809E38)
            r5.setImageResource(r0)
            r0 = 2131689496(0x7f0f0018, float:1.900801E38)
            java.lang.String r1 = "AccDescrCameraFlashOff"
            java.lang.String r0 = im.uwrkaxlmjj.messenger.LocaleController.getString(r1, r0)
            r5.setContentDescription(r0)
        L74:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.setCameraFlashModeIcon(android.widget.ImageView, java.lang.String):void");
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean onCustomMeasure(View view, int width, int height) {
        boolean isPortrait = width < height;
        FrameLayout frameLayout = this.cameraIcon;
        if (view == frameLayout) {
            frameLayout.measure(View.MeasureSpec.makeMeasureSpec(this.itemSize, 1073741824), View.MeasureSpec.makeMeasureSpec((this.itemSize - this.cameraViewOffsetBottomY) - this.cameraViewOffsetY, 1073741824));
            return true;
        }
        CameraView cameraView = this.cameraView;
        if (view == cameraView) {
            if (this.cameraOpened && !this.cameraAnimationInProgress) {
                cameraView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(height, 1073741824));
                return true;
            }
        } else {
            FrameLayout frameLayout2 = this.cameraPanel;
            if (view == frameLayout2) {
                if (isPortrait) {
                    frameLayout2.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(126.0f), 1073741824));
                } else {
                    frameLayout2.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(126.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(height, 1073741824));
                }
                return true;
            }
            ZoomControlView zoomControlView = this.zoomControlView;
            if (view == zoomControlView) {
                if (isPortrait) {
                    zoomControlView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(50.0f), 1073741824));
                } else {
                    zoomControlView.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(50.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(height, 1073741824));
                }
                return true;
            }
            RecyclerListView recyclerListView = this.cameraPhotoRecyclerView;
            if (view == recyclerListView) {
                this.cameraPhotoRecyclerViewIgnoreLayout = true;
                if (isPortrait) {
                    recyclerListView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(80.0f), 1073741824));
                    if (this.cameraPhotoLayoutManager.getOrientation() != 0) {
                        this.cameraPhotoRecyclerView.setPadding(AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f), 0);
                        this.cameraPhotoLayoutManager.setOrientation(0);
                        this.cameraAttachAdapter.notifyDataSetChanged();
                    }
                } else {
                    recyclerListView.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(80.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(height, 1073741824));
                    if (this.cameraPhotoLayoutManager.getOrientation() != 1) {
                        this.cameraPhotoRecyclerView.setPadding(0, AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f));
                        this.cameraPhotoLayoutManager.setOrientation(1);
                        this.cameraAttachAdapter.notifyDataSetChanged();
                    }
                }
                this.cameraPhotoRecyclerViewIgnoreLayout = false;
                return true;
            }
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean onCustomLayout(View view, int left, int top, int right, int bottom) {
        int cx;
        int cy;
        int width = right - left;
        int height = bottom - top;
        boolean isPortrait = width < height;
        if (view == this.cameraPanel) {
            if (isPortrait) {
                if (this.cameraPhotoRecyclerView.getVisibility() == 0) {
                    this.cameraPanel.layout(0, bottom - AndroidUtilities.dp(222.0f), width, bottom - AndroidUtilities.dp(96.0f));
                } else {
                    this.cameraPanel.layout(0, bottom - AndroidUtilities.dp(126.0f), width, bottom);
                }
            } else if (this.cameraPhotoRecyclerView.getVisibility() == 0) {
                this.cameraPanel.layout(right - AndroidUtilities.dp(222.0f), 0, right - AndroidUtilities.dp(96.0f), height);
            } else {
                this.cameraPanel.layout(right - AndroidUtilities.dp(126.0f), 0, right, height);
            }
            return true;
        }
        if (view == this.zoomControlView) {
            if (isPortrait) {
                if (this.cameraPhotoRecyclerView.getVisibility() == 0) {
                    this.zoomControlView.layout(0, bottom - AndroidUtilities.dp(310.0f), width, bottom - AndroidUtilities.dp(260.0f));
                } else {
                    this.zoomControlView.layout(0, bottom - AndroidUtilities.dp(176.0f), width, bottom - AndroidUtilities.dp(126.0f));
                }
            } else if (this.cameraPhotoRecyclerView.getVisibility() == 0) {
                this.zoomControlView.layout(right - AndroidUtilities.dp(310.0f), 0, right - AndroidUtilities.dp(260.0f), height);
            } else {
                this.zoomControlView.layout(right - AndroidUtilities.dp(176.0f), 0, right - AndroidUtilities.dp(126.0f), height);
            }
            return true;
        }
        TextView textView = this.counterTextView;
        if (view == textView) {
            if (isPortrait) {
                cx = (width - textView.getMeasuredWidth()) / 2;
                cy = bottom - AndroidUtilities.dp(167.0f);
                this.counterTextView.setRotation(0.0f);
                if (this.cameraPhotoRecyclerView.getVisibility() == 0) {
                    cy -= AndroidUtilities.dp(96.0f);
                }
            } else {
                cx = right - AndroidUtilities.dp(167.0f);
                cy = (height / 2) + (this.counterTextView.getMeasuredWidth() / 2);
                this.counterTextView.setRotation(-90.0f);
                if (this.cameraPhotoRecyclerView.getVisibility() == 0) {
                    cx -= AndroidUtilities.dp(96.0f);
                }
            }
            TextView textView2 = this.counterTextView;
            textView2.layout(cx, cy, textView2.getMeasuredWidth() + cx, this.counterTextView.getMeasuredHeight() + cy);
            return true;
        }
        if (view != this.cameraPhotoRecyclerView) {
            return false;
        }
        if (!isPortrait) {
            int cx2 = (left + width) - AndroidUtilities.dp(88.0f);
            view.layout(cx2, 0, view.getMeasuredWidth() + cx2, view.getMeasuredHeight());
        } else {
            int cy2 = height - AndroidUtilities.dp(88.0f);
            view.layout(0, cy2, view.getMeasuredWidth(), view.getMeasuredHeight() + cy2);
        }
        return true;
    }

    public void onPause() {
        ShutterButton shutterButton = this.shutterButton;
        if (shutterButton == null) {
            return;
        }
        if (!this.requestingPermissions) {
            if (this.cameraView != null && shutterButton.getState() == ShutterButton.State.RECORDING) {
                resetRecordState();
                CameraController.getInstance().stopVideoRecording(this.cameraView.getCameraSession(), false);
                this.shutterButton.setState(ShutterButton.State.DEFAULT, true);
            }
            if (this.cameraOpened) {
                closeCamera(false);
            }
            hideCamera(true);
        } else {
            if (this.cameraView != null && shutterButton.getState() == ShutterButton.State.RECORDING) {
                this.shutterButton.setState(ShutterButton.State.DEFAULT, true);
            }
            this.requestingPermissions = false;
        }
        this.paused = true;
    }

    public void onResume() {
        this.paused = false;
        if (isShowing() && !isDismissed()) {
            checkCamera(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openCamera(boolean animated) {
        CameraView cameraView = this.cameraView;
        if (cameraView == null || this.cameraInitAnimation != null || !cameraView.isInitied()) {
            return;
        }
        if (cameraPhotos.isEmpty()) {
            this.counterTextView.setVisibility(4);
            this.cameraPhotoRecyclerView.setVisibility(8);
        } else {
            this.counterTextView.setVisibility(0);
            this.cameraPhotoRecyclerView.setVisibility(0);
        }
        if (this.commentTextView.isKeyboardVisible() && isFocusable()) {
            this.commentTextView.closeKeyboard();
        }
        this.zoomControlView.setVisibility(0);
        this.zoomControlView.setAlpha(0.0f);
        this.cameraPanel.setVisibility(0);
        this.cameraPanel.setTag(null);
        int[] iArr = this.animateCameraValues;
        iArr[0] = 0;
        int i = this.itemSize;
        iArr[1] = i - this.cameraViewOffsetX;
        iArr[2] = (i - this.cameraViewOffsetY) - this.cameraViewOffsetBottomY;
        if (animated) {
            this.cameraAnimationInProgress = true;
            ArrayList<Animator> animators = new ArrayList<>();
            animators.add(ObjectAnimator.ofFloat(this, "cameraOpenProgress", 0.0f, 1.0f));
            animators.add(ObjectAnimator.ofFloat(this.cameraPanel, (Property<FrameLayout, Float>) View.ALPHA, 1.0f));
            animators.add(ObjectAnimator.ofFloat(this.counterTextView, (Property<TextView, Float>) View.ALPHA, 1.0f));
            animators.add(ObjectAnimator.ofFloat(this.cameraPhotoRecyclerView, (Property<RecyclerListView, Float>) View.ALPHA, 1.0f));
            int a = 0;
            while (true) {
                if (a >= 2) {
                    break;
                }
                if (this.flashModeButton[a].getVisibility() == 0) {
                    animators.add(ObjectAnimator.ofFloat(this.flashModeButton[a], (Property<ImageView, Float>) View.ALPHA, 1.0f));
                    break;
                }
                a++;
            }
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.playTogether(animators);
            animatorSet.setDuration(200L);
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.20
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    ImagePreSelectorActivity.this.cameraAnimationInProgress = false;
                    if (Build.VERSION.SDK_INT >= 21 && ImagePreSelectorActivity.this.cameraView != null) {
                        ImagePreSelectorActivity.this.cameraView.invalidateOutline();
                    }
                    if (ImagePreSelectorActivity.this.cameraOpened) {
                        ImagePreSelectorActivity.this.delegate.onCameraOpened();
                    }
                }
            });
            animatorSet.start();
        } else {
            setCameraOpenProgress(1.0f);
            this.cameraPanel.setAlpha(1.0f);
            this.counterTextView.setAlpha(1.0f);
            this.cameraPhotoRecyclerView.setAlpha(1.0f);
            int a2 = 0;
            while (true) {
                if (a2 >= 2) {
                    break;
                }
                if (this.flashModeButton[a2].getVisibility() == 0) {
                    this.flashModeButton[a2].setAlpha(1.0f);
                    break;
                }
                a2++;
            }
            this.delegate.onCameraOpened();
        }
        if (Build.VERSION.SDK_INT >= 21) {
            this.cameraView.setSystemUiVisibility(1028);
        }
        this.cameraOpened = true;
        this.cameraView.setImportantForAccessibility(2);
        if (Build.VERSION.SDK_INT >= 19) {
            this.gridView.setImportantForAccessibility(4);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:55:0x0105  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onActivityResultFragment(int r23, android.content.Intent r24, java.lang.String r25) {
        /*
            Method dump skipped, instruction units count: 438
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.onActivityResultFragment(int, android.content.Intent, java.lang.String):void");
    }

    public void closeCamera(boolean animated) {
        if (this.takingPhoto || this.cameraView == null) {
            return;
        }
        int[] iArr = this.animateCameraValues;
        int i = this.itemSize;
        iArr[1] = i - this.cameraViewOffsetX;
        iArr[2] = (i - this.cameraViewOffsetY) - this.cameraViewOffsetBottomY;
        Runnable runnable = this.zoomControlHideRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.zoomControlHideRunnable = null;
        }
        if (!animated) {
            this.animateCameraValues[0] = 0;
            setCameraOpenProgress(0.0f);
            this.cameraPanel.setAlpha(0.0f);
            this.cameraPanel.setVisibility(8);
            this.zoomControlView.setAlpha(0.0f);
            this.zoomControlView.setTag(null);
            this.zoomControlView.setVisibility(8);
            this.cameraPhotoRecyclerView.setAlpha(0.0f);
            this.counterTextView.setAlpha(0.0f);
            this.cameraPhotoRecyclerView.setVisibility(8);
            int a = 0;
            while (true) {
                if (a >= 2) {
                    break;
                }
                if (this.flashModeButton[a].getVisibility() != 0) {
                    a++;
                } else {
                    this.flashModeButton[a].setAlpha(0.0f);
                    break;
                }
            }
            this.cameraOpened = false;
            if (Build.VERSION.SDK_INT >= 21) {
                this.cameraView.setSystemUiVisibility(1024);
            }
        } else {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.cameraView.getLayoutParams();
            int[] iArr2 = this.animateCameraValues;
            int translationY = (int) this.cameraView.getTranslationY();
            layoutParams.topMargin = translationY;
            iArr2[0] = translationY;
            this.cameraView.setLayoutParams(layoutParams);
            this.cameraView.setTranslationY(0.0f);
            this.cameraAnimationInProgress = true;
            ArrayList<Animator> animators = new ArrayList<>();
            animators.add(ObjectAnimator.ofFloat(this, "cameraOpenProgress", 0.0f));
            animators.add(ObjectAnimator.ofFloat(this.cameraPanel, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
            animators.add(ObjectAnimator.ofFloat(this.zoomControlView, (Property<ZoomControlView, Float>) View.ALPHA, 0.0f));
            animators.add(ObjectAnimator.ofFloat(this.counterTextView, (Property<TextView, Float>) View.ALPHA, 0.0f));
            animators.add(ObjectAnimator.ofFloat(this.cameraPhotoRecyclerView, (Property<RecyclerListView, Float>) View.ALPHA, 0.0f));
            int a2 = 0;
            while (true) {
                if (a2 >= 2) {
                    break;
                }
                if (this.flashModeButton[a2].getVisibility() == 0) {
                    animators.add(ObjectAnimator.ofFloat(this.flashModeButton[a2], (Property<ImageView, Float>) View.ALPHA, 0.0f));
                    break;
                }
                a2++;
            }
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.playTogether(animators);
            animatorSet.setDuration(200L);
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.21
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    ImagePreSelectorActivity.this.cameraAnimationInProgress = false;
                    if (Build.VERSION.SDK_INT >= 21 && ImagePreSelectorActivity.this.cameraView != null) {
                        ImagePreSelectorActivity.this.cameraView.invalidateOutline();
                    }
                    ImagePreSelectorActivity.this.cameraOpened = false;
                    if (ImagePreSelectorActivity.this.cameraPanel != null) {
                        ImagePreSelectorActivity.this.cameraPanel.setVisibility(8);
                    }
                    if (ImagePreSelectorActivity.this.zoomControlView != null) {
                        ImagePreSelectorActivity.this.zoomControlView.setVisibility(8);
                        ImagePreSelectorActivity.this.zoomControlView.setTag(null);
                    }
                    if (ImagePreSelectorActivity.this.cameraPhotoRecyclerView != null) {
                        ImagePreSelectorActivity.this.cameraPhotoRecyclerView.setVisibility(8);
                    }
                    if (Build.VERSION.SDK_INT >= 21 && ImagePreSelectorActivity.this.cameraView != null) {
                        ImagePreSelectorActivity.this.cameraView.setSystemUiVisibility(1024);
                    }
                }
            });
            animatorSet.start();
        }
        this.cameraView.setImportantForAccessibility(0);
        if (Build.VERSION.SDK_INT >= 19) {
            this.gridView.setImportantForAccessibility(0);
        }
    }

    public void setCameraOpenProgress(float value) {
        float endWidth;
        float endHeight;
        if (this.cameraView == null) {
            return;
        }
        this.cameraOpenProgress = value;
        int[] iArr = this.animateCameraValues;
        float startWidth = iArr[1];
        float startHeight = iArr[2];
        boolean isPortrait = AndroidUtilities.displaySize.x < AndroidUtilities.displaySize.y;
        if (isPortrait) {
            endWidth = (this.container.getWidth() - getLeftInset()) - getRightInset();
            endHeight = this.container.getHeight();
        } else {
            endWidth = (this.container.getWidth() - getLeftInset()) - getRightInset();
            endHeight = this.container.getHeight();
        }
        if (value == 0.0f) {
            this.cameraView.setClipTop(this.cameraViewOffsetY);
            this.cameraView.setClipBottom(this.cameraViewOffsetBottomY);
            this.cameraView.setTranslationX(this.cameraViewLocation[0]);
            this.cameraView.setTranslationY(this.cameraViewLocation[1]);
            this.cameraIcon.setTranslationX(this.cameraViewLocation[0]);
            this.cameraIcon.setTranslationY(this.cameraViewLocation[1]);
        } else if (this.cameraView.getTranslationX() != 0.0f || this.cameraView.getTranslationY() != 0.0f) {
            this.cameraView.setTranslationX(0.0f);
            this.cameraView.setTranslationY(0.0f);
        }
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.cameraView.getLayoutParams();
        layoutParams.width = (int) (((endWidth - startWidth) * value) + startWidth);
        layoutParams.height = (int) (((endHeight - startHeight) * value) + startHeight);
        if (value != 0.0f) {
            this.cameraView.setClipTop((int) (this.cameraViewOffsetY * (1.0f - value)));
            this.cameraView.setClipBottom((int) (this.cameraViewOffsetBottomY * (1.0f - value)));
            layoutParams.leftMargin = (int) (this.cameraViewLocation[0] * (1.0f - value));
            int[] iArr2 = this.animateCameraValues;
            layoutParams.topMargin = (int) (iArr2[0] + ((this.cameraViewLocation[1] - iArr2[0]) * (1.0f - value)));
        } else {
            layoutParams.leftMargin = 0;
            layoutParams.topMargin = 0;
        }
        this.cameraView.setLayoutParams(layoutParams);
        if (value > 0.5f) {
            this.cameraIcon.setAlpha(0.0f);
        } else {
            this.cameraIcon.setAlpha(1.0f - (value / 0.5f));
        }
        if (Build.VERSION.SDK_INT >= 21) {
            this.cameraView.invalidateOutline();
        }
    }

    public float getCameraOpenProgress() {
        return this.cameraOpenProgress;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkCameraViewPosition() {
        RecyclerView.ViewHolder holder;
        if (Build.VERSION.SDK_INT >= 21) {
            CameraView cameraView = this.cameraView;
            if (cameraView != null) {
                cameraView.invalidateOutline();
            }
            RecyclerView.ViewHolder holder2 = this.gridView.findViewHolderForAdapterPosition(this.itemsPerRow - 1);
            if (holder2 != null) {
                holder2.itemView.invalidateOutline();
            }
            if ((!this.adapter.needCamera || !this.deviceHasGoodCamera || this.selectedAlbumEntry != this.galleryAlbumEntry) && (holder = this.gridView.findViewHolderForAdapterPosition(0)) != null) {
                holder.itemView.invalidateOutline();
            }
        }
        if (!this.deviceHasGoodCamera) {
            return;
        }
        int count = this.gridView.getChildCount();
        int a = 0;
        while (true) {
            if (a >= count) {
                break;
            }
            View child = this.gridView.getChildAt(a);
            if (!(child instanceof PhotoAttachCameraCell)) {
                a++;
            } else if (Build.VERSION.SDK_INT < 19 || child.isAttachedToWindow()) {
                child.getLocationInWindow(this.cameraViewLocation);
                int[] iArr = this.cameraViewLocation;
                iArr[0] = iArr[0] - getLeftInset();
                float listViewX = this.gridView.getX() - getLeftInset();
                int[] iArr2 = this.cameraViewLocation;
                if (iArr2[0] < listViewX) {
                    int i = (int) (listViewX - iArr2[0]);
                    this.cameraViewOffsetX = i;
                    if (i >= this.itemSize) {
                        this.cameraViewOffsetX = 0;
                        iArr2[0] = AndroidUtilities.dp(-400.0f);
                        this.cameraViewLocation[1] = 0;
                    } else {
                        iArr2[0] = iArr2[0] + i;
                    }
                } else {
                    this.cameraViewOffsetX = 0;
                }
                int maxY = (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0) + ActionBar.getCurrentActionBarHeight();
                int[] iArr3 = this.cameraViewLocation;
                if (iArr3[1] < maxY) {
                    int i2 = maxY - iArr3[1];
                    this.cameraViewOffsetY = i2;
                    if (i2 >= this.itemSize) {
                        this.cameraViewOffsetY = 0;
                        iArr3[0] = AndroidUtilities.dp(-400.0f);
                        this.cameraViewLocation[1] = 0;
                    } else {
                        iArr3[1] = iArr3[1] + i2;
                    }
                } else {
                    this.cameraViewOffsetY = 0;
                }
                int containerHeight = this.containerView.getMeasuredHeight();
                int keyboardSize = this.sizeNotifierFrameLayout.getKeyboardHeight();
                if (!AndroidUtilities.isInMultiwindow && keyboardSize <= AndroidUtilities.dp(20.0f)) {
                    containerHeight -= this.commentTextView.getEmojiPadding();
                }
                int maxY2 = (int) (containerHeight + this.containerView.getTranslationY());
                int[] iArr4 = this.cameraViewLocation;
                int i3 = iArr4[1];
                int i4 = this.itemSize;
                if (i3 + i4 > maxY2) {
                    int i5 = (iArr4[1] + i4) - maxY2;
                    this.cameraViewOffsetBottomY = i5;
                    if (i5 >= i4) {
                        this.cameraViewOffsetBottomY = 0;
                        iArr4[0] = AndroidUtilities.dp(-400.0f);
                        this.cameraViewLocation[1] = 0;
                    }
                } else {
                    this.cameraViewOffsetBottomY = 0;
                }
                applyCameraViewPosition();
                return;
            }
        }
        this.cameraViewOffsetX = 0;
        this.cameraViewOffsetY = 0;
        this.cameraViewLocation[0] = AndroidUtilities.dp(-400.0f);
        this.cameraViewLocation[1] = 0;
        applyCameraViewPosition();
    }

    private void applyCameraViewPosition() {
        CameraView cameraView = this.cameraView;
        if (cameraView != null) {
            if (!this.cameraOpened) {
                cameraView.setTranslationX(this.cameraViewLocation[0]);
                this.cameraView.setTranslationY(this.cameraViewLocation[1]);
            }
            this.cameraIcon.setTranslationX(this.cameraViewLocation[0]);
            this.cameraIcon.setTranslationY(this.cameraViewLocation[1]);
            int i = this.itemSize;
            int finalWidth = i - this.cameraViewOffsetX;
            int i2 = this.cameraViewOffsetY;
            int finalHeight = (i - i2) - this.cameraViewOffsetBottomY;
            if (!this.cameraOpened) {
                this.cameraView.setClipTop(i2);
                this.cameraView.setClipBottom(this.cameraViewOffsetBottomY);
                final FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.cameraView.getLayoutParams();
                if (layoutParams.height != finalHeight || layoutParams.width != finalWidth) {
                    layoutParams.width = finalWidth;
                    layoutParams.height = finalHeight;
                    this.cameraView.setLayoutParams(layoutParams);
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$zwLlAHJWaIF9zTLC5Y-xWQhWTJQ
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$applyCameraViewPosition$12$ImagePreSelectorActivity(layoutParams);
                        }
                    });
                }
            }
            final FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.cameraIcon.getLayoutParams();
            if (layoutParams2.height != finalHeight || layoutParams2.width != finalWidth) {
                layoutParams2.width = finalWidth;
                layoutParams2.height = finalHeight;
                this.cameraIcon.setLayoutParams(layoutParams2);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$BG8HicAyLsZd0QIhmkz360ZaN10
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$applyCameraViewPosition$13$ImagePreSelectorActivity(layoutParams2);
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$applyCameraViewPosition$12$ImagePreSelectorActivity(FrameLayout.LayoutParams layoutParamsFinal) {
        CameraView cameraView = this.cameraView;
        if (cameraView != null) {
            cameraView.setLayoutParams(layoutParamsFinal);
        }
    }

    public /* synthetic */ void lambda$applyCameraViewPosition$13$ImagePreSelectorActivity(FrameLayout.LayoutParams layoutParamsFinal) {
        FrameLayout frameLayout = this.cameraIcon;
        if (frameLayout != null) {
            frameLayout.setLayoutParams(layoutParamsFinal);
        }
    }

    public void showCamera() {
        if (this.paused || !this.mediaEnabled) {
            return;
        }
        if (this.cameraView == null) {
            CameraView cameraView = new CameraView(this.mActivity, this.openWithFrontFaceCamera);
            this.cameraView = cameraView;
            cameraView.setFocusable(true);
            if (Build.VERSION.SDK_INT >= 21) {
                this.cameraView.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.22
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view, Outline outline) {
                        if (ImagePreSelectorActivity.this.cameraAnimationInProgress) {
                            int rad = AndroidUtilities.dp(ImagePreSelectorActivity.this.cornerRadius * 8.0f * ImagePreSelectorActivity.this.cameraOpenProgress);
                            outline.setRoundRect(0, 0, view.getMeasuredWidth() + rad, view.getMeasuredHeight() + rad, rad);
                        } else if (!ImagePreSelectorActivity.this.cameraAnimationInProgress && !ImagePreSelectorActivity.this.cameraOpened) {
                            int rad2 = AndroidUtilities.dp(ImagePreSelectorActivity.this.cornerRadius * 8.0f);
                            outline.setRoundRect(0, 0, view.getMeasuredWidth() + rad2, view.getMeasuredHeight() + rad2, rad2);
                        } else {
                            outline.setRect(0, 0, view.getMeasuredWidth(), view.getMeasuredHeight());
                        }
                    }
                });
                this.cameraView.setClipToOutline(true);
            }
            this.cameraView.setContentDescription(LocaleController.getString("AccDescrInstantCamera", R.string.AccDescrInstantCamera));
            BottomSheet.ContainerView containerView = this.container;
            CameraView cameraView2 = this.cameraView;
            int i = this.itemSize;
            containerView.addView(cameraView2, 1, new FrameLayout.LayoutParams(i, i));
            this.cameraView.setDelegate(new CameraView.CameraViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.23
                @Override // im.uwrkaxlmjj.messenger.camera.CameraView.CameraViewDelegate
                public void onCameraCreated(Camera camera) {
                }

                @Override // im.uwrkaxlmjj.messenger.camera.CameraView.CameraViewDelegate
                public void onCameraInit() {
                    String current = ImagePreSelectorActivity.this.cameraView.getCameraSession().getCurrentFlashMode();
                    String next = ImagePreSelectorActivity.this.cameraView.getCameraSession().getNextFlashMode();
                    if (current.equals(next)) {
                        for (int a = 0; a < 2; a++) {
                            ImagePreSelectorActivity.this.flashModeButton[a].setVisibility(4);
                            ImagePreSelectorActivity.this.flashModeButton[a].setAlpha(0.0f);
                            ImagePreSelectorActivity.this.flashModeButton[a].setTranslationY(0.0f);
                        }
                    } else {
                        ImagePreSelectorActivity imagePreSelectorActivity = ImagePreSelectorActivity.this;
                        imagePreSelectorActivity.setCameraFlashModeIcon(imagePreSelectorActivity.flashModeButton[0], ImagePreSelectorActivity.this.cameraView.getCameraSession().getCurrentFlashMode());
                        int a2 = 0;
                        while (a2 < 2) {
                            ImagePreSelectorActivity.this.flashModeButton[a2].setVisibility(a2 == 0 ? 0 : 4);
                            ImagePreSelectorActivity.this.flashModeButton[a2].setAlpha((a2 == 0 && ImagePreSelectorActivity.this.cameraOpened) ? 1.0f : 0.0f);
                            ImagePreSelectorActivity.this.flashModeButton[a2].setTranslationY(0.0f);
                            a2++;
                        }
                    }
                    ImagePreSelectorActivity.this.switchCameraButton.setImageResource(ImagePreSelectorActivity.this.cameraView.isFrontface() ? R.drawable.camera_revert1 : R.drawable.camera_revert2);
                    ImagePreSelectorActivity.this.switchCameraButton.setVisibility(ImagePreSelectorActivity.this.cameraView.hasFrontFaceCamera() ? 0 : 4);
                    if (!ImagePreSelectorActivity.this.cameraOpened) {
                        ImagePreSelectorActivity.this.cameraInitAnimation = new AnimatorSet();
                        ImagePreSelectorActivity.this.cameraInitAnimation.playTogether(ObjectAnimator.ofFloat(ImagePreSelectorActivity.this.cameraView, (Property<CameraView, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(ImagePreSelectorActivity.this.cameraIcon, (Property<FrameLayout, Float>) View.ALPHA, 0.0f, 1.0f));
                        ImagePreSelectorActivity.this.cameraInitAnimation.setDuration(180L);
                        ImagePreSelectorActivity.this.cameraInitAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.23.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (animation.equals(ImagePreSelectorActivity.this.cameraInitAnimation)) {
                                    ImagePreSelectorActivity.this.cameraInitAnimation = null;
                                    int count = ImagePreSelectorActivity.this.gridView.getChildCount();
                                    for (int a3 = 0; a3 < count; a3++) {
                                        View child = ImagePreSelectorActivity.this.gridView.getChildAt(a3);
                                        if (child instanceof PhotoAttachCameraCell) {
                                            child.setVisibility(4);
                                            return;
                                        }
                                    }
                                }
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationCancel(Animator animation) {
                                ImagePreSelectorActivity.this.cameraInitAnimation = null;
                            }
                        });
                        ImagePreSelectorActivity.this.cameraInitAnimation.start();
                    }
                }
            });
            if (this.cameraIcon == null) {
                FrameLayout frameLayout = new FrameLayout(this.mActivity) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.24
                    @Override // android.view.View
                    protected void onDraw(Canvas canvas) {
                        int w = ImagePreSelectorActivity.this.cameraDrawable.getIntrinsicWidth();
                        int h = ImagePreSelectorActivity.this.cameraDrawable.getIntrinsicHeight();
                        int x = (ImagePreSelectorActivity.this.itemSize - w) / 2;
                        int y = (ImagePreSelectorActivity.this.itemSize - h) / 2;
                        if (ImagePreSelectorActivity.this.cameraViewOffsetY != 0) {
                            y -= ImagePreSelectorActivity.this.cameraViewOffsetY;
                        }
                        ImagePreSelectorActivity.this.cameraDrawable.setBounds(x, y, x + w, y + h);
                        ImagePreSelectorActivity.this.cameraDrawable.draw(canvas);
                    }
                };
                this.cameraIcon = frameLayout;
                frameLayout.setWillNotDraw(false);
                this.cameraIcon.setClipChildren(true);
            }
            BottomSheet.ContainerView containerView2 = this.container;
            FrameLayout frameLayout2 = this.cameraIcon;
            int i2 = this.itemSize;
            containerView2.addView(frameLayout2, 2, new FrameLayout.LayoutParams(i2, i2));
            this.cameraView.setAlpha(this.mediaEnabled ? 1.0f : 0.2f);
            this.cameraView.setEnabled(this.mediaEnabled);
            this.cameraIcon.setAlpha(this.mediaEnabled ? 1.0f : 0.2f);
            this.cameraIcon.setEnabled(this.mediaEnabled);
            checkCameraViewPosition();
        }
        ZoomControlView zoomControlView = this.zoomControlView;
        if (zoomControlView != null) {
            zoomControlView.setZoom(0.0f, false);
            this.cameraZoom = 0.0f;
        }
        this.cameraView.setTranslationX(this.cameraViewLocation[0]);
        this.cameraView.setTranslationY(this.cameraViewLocation[1]);
        this.cameraIcon.setTranslationX(this.cameraViewLocation[0]);
        this.cameraIcon.setTranslationY(this.cameraViewLocation[1]);
    }

    public void hideCamera(boolean async) {
        if (!this.deviceHasGoodCamera || this.cameraView == null) {
            return;
        }
        saveLastCameraBitmap();
        this.cameraView.destroy(async, null);
        AnimatorSet animatorSet = this.cameraInitAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.cameraInitAnimation = null;
        }
        this.container.removeView(this.cameraView);
        this.container.removeView(this.cameraIcon);
        this.cameraView = null;
        this.cameraIcon = null;
        int count = this.gridView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.gridView.getChildAt(a);
            if (child instanceof PhotoAttachCameraCell) {
                child.setVisibility(0);
                return;
            }
        }
    }

    private void saveLastCameraBitmap() {
        Bitmap bitmap = null;
        FileOutputStream stream = null;
        try {
            try {
                TextureView textureView = this.cameraView.getTextureView();
                bitmap = textureView.getBitmap();
                if (bitmap != null) {
                    Bitmap newBitmap = Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(), bitmap.getHeight(), this.cameraView.getMatrix(), true);
                    bitmap.recycle();
                    bitmap = newBitmap;
                    Bitmap lastBitmap = Bitmap.createScaledBitmap(bitmap, 80, (int) (bitmap.getHeight() / (bitmap.getWidth() / 80.0f)), true);
                    if (lastBitmap != null) {
                        if (lastBitmap != bitmap) {
                            bitmap.recycle();
                        }
                        Utilities.blurBitmap(lastBitmap, 7, 1, lastBitmap.getWidth(), lastBitmap.getHeight(), lastBitmap.getRowBytes());
                        File file = new File(ApplicationLoader.getFilesDirFixed(), "cthumb.jpg");
                        stream = new FileOutputStream(file);
                        lastBitmap.compress(Bitmap.CompressFormat.JPEG, 87, stream);
                        lastBitmap.recycle();
                    }
                }
                if (bitmap != null) {
                    bitmap.recycle();
                }
                if (stream != null) {
                    stream.close();
                }
            } catch (Throwable th) {
                if (bitmap != null) {
                    bitmap.recycle();
                }
                if (stream != null) {
                    stream.close();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.albumsDidLoad) {
            if (this.adapter != null) {
                MediaController.AlbumEntry albumEntry = MediaController.allMediaAlbumEntry;
                this.galleryAlbumEntry = albumEntry;
                if (this.selectedAlbumEntry == null) {
                    this.selectedAlbumEntry = albumEntry;
                } else {
                    int a = 0;
                    while (true) {
                        if (a >= MediaController.allMediaAlbums.size()) {
                            break;
                        }
                        MediaController.AlbumEntry entry = MediaController.allMediaAlbums.get(a);
                        if (entry.bucketId != this.selectedAlbumEntry.bucketId || entry.videoOnly != this.selectedAlbumEntry.videoOnly) {
                            a++;
                        } else {
                            this.selectedAlbumEntry = entry;
                            break;
                        }
                    }
                }
                this.loading = false;
                this.progressView.showTextView();
                this.adapter.notifyDataSetChanged();
                this.cameraAttachAdapter.notifyDataSetChanged();
                if (!selectedPhotosOrder.isEmpty() && this.galleryAlbumEntry != null) {
                    int N = selectedPhotosOrder.size();
                    for (int a2 = 0; a2 < N; a2++) {
                        int imageId = ((Integer) selectedPhotosOrder.get(a2)).intValue();
                        MediaController.PhotoEntry entry2 = this.galleryAlbumEntry.photosByIds.get(imageId);
                        if (entry2 != null) {
                            selectedPhotos.put(Integer.valueOf(imageId), entry2);
                        }
                    }
                }
                updateAlbumsDropDown();
                return;
            }
            return;
        }
        if (id == NotificationCenter.cameraInitied) {
            checkCamera(false);
        }
    }

    private void updateAlbumsDropDown() {
        this.dropDownContainer.removeAllSubItems();
        if (this.mediaEnabled) {
            final ArrayList<MediaController.AlbumEntry> albums = MediaController.allMediaAlbums;
            ArrayList<MediaController.AlbumEntry> arrayList = new ArrayList<>(albums);
            this.dropDownAlbums = arrayList;
            Collections.sort(arrayList, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$WLlv9Un3tc-RUuYWpvpdJvTH358
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return ImagePreSelectorActivity.lambda$updateAlbumsDropDown$14(albums, (MediaController.AlbumEntry) obj, (MediaController.AlbumEntry) obj2);
                }
            });
        } else {
            this.dropDownAlbums = new ArrayList<>();
        }
        if (this.dropDownAlbums.isEmpty()) {
            this.dropDown.setCompoundDrawablesWithIntrinsicBounds((Drawable) null, (Drawable) null, (Drawable) null, (Drawable) null);
            return;
        }
        this.dropDown.setCompoundDrawablesWithIntrinsicBounds((Drawable) null, (Drawable) null, this.dropDownDrawable, (Drawable) null);
        int N = this.dropDownAlbums.size();
        for (int a = 0; a < N; a++) {
            this.dropDownContainer.addSubItem(a + 10, this.dropDownAlbums.get(a).bucketName);
        }
    }

    static /* synthetic */ int lambda$updateAlbumsDropDown$14(ArrayList albums, MediaController.AlbumEntry o1, MediaController.AlbumEntry o2) {
        int index1;
        int index2;
        if (o1.bucketId == 0 && o2.bucketId != 0) {
            return -1;
        }
        if ((o1.bucketId == 0 || o2.bucketId != 0) && (index1 = albums.indexOf(o1)) <= (index2 = albums.indexOf(o2))) {
            return index1 < index2 ? -1 : 0;
        }
        return 1;
    }

    private void updateSelectedPosition() {
        float moveProgress;
        int finalMove;
        int t = (this.scrollOffsetY - this.backgroundPaddingTop) - AndroidUtilities.dp(39.0f);
        if (this.backgroundPaddingTop + t < ActionBar.getCurrentActionBarHeight()) {
            float toMove = AndroidUtilities.dp(43.0f);
            moveProgress = Math.min(1.0f, ((ActionBar.getCurrentActionBarHeight() - t) - this.backgroundPaddingTop) / toMove);
            this.cornerRadius = 1.0f - moveProgress;
        } else {
            moveProgress = 0.0f;
            this.cornerRadius = 1.0f;
        }
        if (AndroidUtilities.isTablet()) {
            finalMove = 16;
        } else if (AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y) {
            finalMove = 6;
        } else {
            finalMove = 12;
        }
        float offset = this.actionBar.getAlpha() == 0.0f ? AndroidUtilities.dp(26.0f) : 0.0f;
        this.selectedTextView.setTranslationY((this.scrollOffsetY - AndroidUtilities.dp((finalMove * moveProgress) + 25.0f)) + offset);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateLayout(boolean animated) {
        if (this.gridView.getChildCount() <= 0) {
            RecyclerListView recyclerListView = this.gridView;
            int paddingTop = recyclerListView.getPaddingTop();
            this.scrollOffsetY = paddingTop;
            recyclerListView.setTopGlowOffset(paddingTop);
            this.containerView.invalidate();
            return;
        }
        View child = this.gridView.getChildAt(0);
        RecyclerListView.Holder holder = (RecyclerListView.Holder) this.gridView.findContainingViewHolder(child);
        int top = child.getTop();
        int newOffset = AndroidUtilities.dp(7.0f);
        if (top >= AndroidUtilities.dp(7.0f) && holder != null && holder.getAdapterPosition() == 0) {
            newOffset = top;
        }
        boolean show = newOffset <= AndroidUtilities.dp(12.0f);
        if ((show && this.actionBar.getTag() == null) || (!show && this.actionBar.getTag() != null)) {
            this.actionBar.setTag(show ? 1 : null);
            AnimatorSet animatorSet = this.actionBarAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.actionBarAnimation = null;
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.actionBarAnimation = animatorSet2;
            animatorSet2.setDuration(180L);
            AnimatorSet animatorSet3 = this.actionBarAnimation;
            Animator[] animatorArr = new Animator[2];
            ActionBar actionBar = this.actionBar;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(actionBar, (Property<ActionBar, Float>) property, fArr);
            View view = this.actionBarShadow;
            Property property2 = View.ALPHA;
            float[] fArr2 = new float[1];
            fArr2[0] = show ? 1.0f : 0.0f;
            animatorArr[1] = ObjectAnimator.ofFloat(view, (Property<View, Float>) property2, fArr2);
            animatorSet3.playTogether(animatorArr);
            this.actionBarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.25
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    ImagePreSelectorActivity.this.actionBarAnimation = null;
                }
            });
            this.actionBarAnimation.start();
        }
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.gridView.getLayoutParams();
        int newOffset2 = newOffset + (layoutParams.topMargin - AndroidUtilities.dp(11.0f));
        if (this.scrollOffsetY != newOffset2) {
            RecyclerListView recyclerListView2 = this.gridView;
            this.scrollOffsetY = newOffset2;
            recyclerListView2.setTopGlowOffset(newOffset2 - layoutParams.topMargin);
            updateSelectedPosition();
            this.containerView.invalidate();
        }
        this.progressView.setTranslationY(this.scrollOffsetY + ((((this.gridView.getMeasuredHeight() - this.scrollOffsetY) - AndroidUtilities.dp(50.0f)) - this.progressView.getMeasuredHeight()) / 2));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return false;
    }

    public void updatePhotosButton() {
        int i;
        String str;
        int max = Math.max(0, selectedPhotosOrder.size());
        ActionBarMenuItem actionBarMenuItem = this.isSkipMenu;
        if (actionBarMenuItem != null) {
            if (max == 0) {
                i = R.string.fc_skip;
                str = "fc_skip";
            } else {
                i = R.string.fc_next;
                str = "fc_next";
            }
            actionBarMenuItem.setText(LocaleController.getString(str, i));
        }
    }

    public void setDelegate(ChatAttachViewDelegate chatAttachViewDelegate) {
        this.delegate = chatAttachViewDelegate;
    }

    public void loadGalleryPhotos() {
        MediaController.AlbumEntry albumEntry = MediaController.allMediaAlbumEntry;
        if (albumEntry == null && Build.VERSION.SDK_INT >= 21) {
            MediaController.loadGalleryPhotosAlbums(0);
        }
    }

    public void init() {
        this.galleryAlbumEntry = MediaController.allMediaAlbumEntry;
        this.commentTextView.setVisibility(4);
        if (Build.VERSION.SDK_INT >= 23) {
            this.noGalleryPermissions = this.mActivity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0;
        }
        if (this.galleryAlbumEntry != null) {
            for (int a = 0; a < Math.min(100, this.galleryAlbumEntry.photos.size()); a++) {
                MediaController.PhotoEntry photoEntry = this.galleryAlbumEntry.photos.get(a);
                photoEntry.reset();
            }
        }
        this.commentTextView.hidePopup(true);
        this.enterCommentEventSent = false;
        setFocusable(false);
        MediaController.AlbumEntry albumEntry = this.galleryAlbumEntry;
        this.selectedAlbumEntry = albumEntry;
        if (albumEntry != null) {
            this.loading = false;
            EmptyTextProgressView emptyTextProgressView = this.progressView;
            if (emptyTextProgressView != null) {
                emptyTextProgressView.showTextView();
            }
        }
        this.dropDown.setText(LocaleController.getString("AllMedia", R.string.AllMedia));
        clearSelectedPhotos();
        updatePhotosCounter(false);
        this.commentTextView.setText("");
        this.cameraPhotoLayoutManager.scrollToPositionWithOffset(0, EditInputFilter.MAX_VALUE);
        this.layoutManager.scrollToPositionWithOffset(0, EditInputFilter.MAX_VALUE);
        updateAlbumsDropDown();
    }

    public HashMap<Object, Object> getSelectedPhotos() {
        return selectedPhotos;
    }

    public ArrayList<Object> getSelectedPhotosOrder() {
        return selectedPhotosOrder;
    }

    public void onDestroy() {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.albumsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.reloadInlineHints);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.cameraInitied);
        this.mActivity = null;
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji != null) {
            editTextEmoji.onDestroy();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public PhotoAttachPhotoCell getCellForIndex(int index) {
        int count = this.gridView.getChildCount();
        for (int a = 0; a < count; a++) {
            View view = this.gridView.getChildAt(a);
            if (view instanceof PhotoAttachPhotoCell) {
                PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                if (((Integer) cell.getImageView().getTag()).intValue() == index) {
                    return cell;
                }
            }
        }
        return null;
    }

    public void checkStorage() {
        if (this.noGalleryPermissions && Build.VERSION.SDK_INT >= 23) {
            boolean z = this.mActivity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0;
            this.noGalleryPermissions = z;
            if (!z) {
                loadGalleryPhotos();
            }
            this.adapter.notifyDataSetChanged();
            this.cameraAttachAdapter.notifyDataSetChanged();
        }
    }

    public void checkCamera(boolean request) {
        PhotoAttachAdapter photoAttachAdapter;
        if (this.mActivity == null) {
            return;
        }
        boolean old = this.deviceHasGoodCamera;
        boolean old2 = this.noCameraPermissions;
        if (!SharedConfig.inappCamera) {
            this.deviceHasGoodCamera = false;
        } else if (Build.VERSION.SDK_INT >= 23) {
            try {
                boolean z = this.mActivity.checkSelfPermission("android.permission.CAMERA") != 0;
                this.noCameraPermissions = z;
                if (z) {
                    if (request) {
                        try {
                            this.mActivity.requestPermissions(new String[]{"android.permission.CAMERA"}, 17);
                        } catch (Exception e) {
                        }
                    }
                    this.deviceHasGoodCamera = false;
                } else {
                    if (request || SharedConfig.hasCameraCache) {
                        CameraController.getInstance().initCamera(null);
                    }
                    this.deviceHasGoodCamera = CameraController.getInstance().isCameraInitied();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        } else {
            if (request || SharedConfig.hasCameraCache) {
                CameraController.getInstance().initCamera(null);
            }
            this.deviceHasGoodCamera = CameraController.getInstance().isCameraInitied();
        }
        if ((old != this.deviceHasGoodCamera || old2 != this.noCameraPermissions) && (photoAttachAdapter = this.adapter) != null) {
            photoAttachAdapter.notifyDataSetChanged();
        }
        if (isShowing() && this.deviceHasGoodCamera && this.mActivity != null && this.backDrawable.getAlpha() != 0 && !this.cameraOpened) {
            showCamera();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegateInterface
    public void onOpenAnimationEnd() {
        NotificationCenter.getInstance(this.currentAccount).setAnimationInProgress(false);
        MediaController.AlbumEntry albumEntry = MediaController.allMediaAlbumEntry;
        if (Build.VERSION.SDK_INT <= 19 && albumEntry == null) {
            MediaController.loadGalleryPhotosAlbums(0);
        }
        checkCamera(true);
        AndroidUtilities.makeAccessibilityAnnouncement(LocaleController.getString("AccDescrAttachButton", R.string.AccDescrAttachButton));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegateInterface
    public void onOpenAnimationStart() {
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegateInterface
    public boolean canDismiss() {
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    public void setAllowDrawContent(boolean value) {
        super.setAllowDrawContent(value);
        checkCameraViewPosition();
    }

    public void setMaxSelectedPhotos(int value, boolean order) {
        if (this.editingMessageObject != null) {
            return;
        }
        this.maxSelectedPhotos = value;
        this.allowOrder = order;
    }

    public void setOpenWithFrontFaceCamera(boolean value) {
        this.openWithFrontFaceCamera = value;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int addToSelectedPhotos(MediaController.PhotoEntry object, int index) {
        Object key = Integer.valueOf(object.imageId);
        if (selectedPhotos.containsKey(key)) {
            selectedPhotos.remove(key);
            int position = selectedPhotosOrder.indexOf(key);
            if (position >= 0) {
                selectedPhotosOrder.remove(position);
            }
            updatePhotosCounter(false);
            updateCheckedPhotoIndices();
            if (index >= 0) {
                object.reset();
                this.photoViewerProvider.updatePhotoAtIndex(index);
            }
            return position;
        }
        selectedPhotos.put(key, object);
        selectedPhotosOrder.add(key);
        updatePhotosCounter(true);
        return -1;
    }

    private void clearSelectedPhotos() {
        if (!selectedPhotos.isEmpty()) {
            for (Map.Entry<Object, Object> entry : selectedPhotos.entrySet()) {
                ((MediaController.PhotoEntry) entry.getValue()).reset();
            }
            selectedPhotos.clear();
            selectedPhotosOrder.clear();
        }
        if (!cameraPhotos.isEmpty()) {
            int size = cameraPhotos.size();
            for (int a = 0; a < size; a++) {
                MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) cameraPhotos.get(a);
                new File(photoEntry.path).delete();
                if (photoEntry.imagePath != null) {
                    new File(photoEntry.imagePath).delete();
                }
                if (photoEntry.thumbPath != null) {
                    new File(photoEntry.thumbPath).delete();
                }
            }
            cameraPhotos.clear();
        }
        updatePhotosButton();
        this.adapter.notifyDataSetChanged();
        this.cameraAttachAdapter.notifyDataSetChanged();
    }

    /* JADX INFO: Access modifiers changed from: private */
    class PhotoAttachAdapter extends RecyclerListView.SelectionAdapter {
        private int itemsCount;
        private Context mContext;
        private boolean needCamera;
        private ArrayList<RecyclerListView.Holder> viewsCache = new ArrayList<>(8);

        public PhotoAttachAdapter(Context context, boolean camera) {
            this.mContext = context;
            this.needCamera = camera;
            for (int a = 0; a < 8; a++) {
                this.viewsCache.add(createHolder());
            }
        }

        public RecyclerListView.Holder createHolder() {
            PhotoAttachPhotoCell cell = new PhotoAttachPhotoCell(this.mContext);
            cell.setNewStyle(true);
            if (Build.VERSION.SDK_INT >= 21 && this == ImagePreSelectorActivity.this.adapter) {
                cell.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.PhotoAttachAdapter.1
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view, Outline outline) {
                        PhotoAttachPhotoCell photoCell = (PhotoAttachPhotoCell) view;
                        int position = ((Integer) photoCell.getTag()).intValue();
                        if (PhotoAttachAdapter.this.needCamera && ImagePreSelectorActivity.this.selectedAlbumEntry == ImagePreSelectorActivity.this.galleryAlbumEntry) {
                            position++;
                        }
                        if (position != 0) {
                            if (position == ImagePreSelectorActivity.this.itemsPerRow - 1) {
                                int rad = AndroidUtilities.dp(ImagePreSelectorActivity.this.cornerRadius * 8.0f);
                                outline.setRoundRect(-rad, 0, view.getMeasuredWidth(), view.getMeasuredHeight() + rad, rad);
                                return;
                            } else {
                                outline.setRect(0, 0, view.getMeasuredWidth(), view.getMeasuredHeight());
                                return;
                            }
                        }
                        int rad2 = AndroidUtilities.dp(ImagePreSelectorActivity.this.cornerRadius * 8.0f);
                        outline.setRoundRect(0, 0, view.getMeasuredWidth() + rad2, view.getMeasuredHeight() + rad2, rad2);
                    }
                });
                cell.setClipToOutline(true);
            }
            cell.setDelegate(new PhotoAttachPhotoCell.PhotoAttachPhotoCellDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreSelectorActivity$PhotoAttachAdapter$cgaJcM4U1znO9ye7T1tlYMhkgQo
                @Override // im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell.PhotoAttachPhotoCellDelegate
                public final void onCheckClick(PhotoAttachPhotoCell photoAttachPhotoCell) {
                    this.f$0.lambda$createHolder$0$ImagePreSelectorActivity$PhotoAttachAdapter(photoAttachPhotoCell);
                }
            });
            return new RecyclerListView.Holder(cell);
        }

        public /* synthetic */ void lambda$createHolder$0$ImagePreSelectorActivity$PhotoAttachAdapter(PhotoAttachPhotoCell v) {
            if (!ImagePreSelectorActivity.this.mediaEnabled) {
                return;
            }
            int index = ((Integer) v.getTag()).intValue();
            MediaController.PhotoEntry photoEntry = v.getPhotoEntry();
            if (photoEntry.isVideo) {
                if (ImagePreSelectorActivity.selectedPhotos != null && ImagePreSelectorActivity.selectedPhotos.size() == 0) {
                    ImagePreSelectorActivity.this.currentSelectMediaType = 2;
                    return;
                }
                return;
            }
            if (ImagePreSelectorActivity.selectedPhotos.isEmpty()) {
                if (ImagePreSelectorActivity.this.maxSelectedPhotos < 9 && ImagePreSelectorActivity.this.currentSelectMediaType == 1 && photoEntry.path.endsWith(".gif")) {
                    FcToastUtils.show((CharSequence) "不能同时选择图片跟Gif动图");
                    return;
                } else if (photoEntry.path.endsWith(".gif")) {
                    ImagePreSelectorActivity.this.currentSelectMediaType = 3;
                } else {
                    ImagePreSelectorActivity.this.currentSelectMediaType = 1;
                }
            } else if (ImagePreSelectorActivity.this.currentSelectMediaType == 3) {
                if (ImagePreSelectorActivity.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId))) {
                    ImagePreSelectorActivity.this.currentSelectMediaType = 0;
                } else if (photoEntry.path.endsWith(".gif")) {
                    FcToastUtils.show((CharSequence) "最多只能选择一张Gif动图");
                    return;
                } else {
                    FcToastUtils.show((CharSequence) "不能同时选择图片跟Gif动图");
                    return;
                }
            } else if (ImagePreSelectorActivity.this.currentSelectMediaType == 1) {
                if (ImagePreSelectorActivity.this.maxSelectedPhotos == 9 && ImagePreSelectorActivity.selectedPhotos.size() == 1 && ImagePreSelectorActivity.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId))) {
                    ImagePreSelectorActivity.this.currentSelectMediaType = 0;
                } else if (photoEntry.path.endsWith(".gif")) {
                    FcToastUtils.show((CharSequence) "不能同时选择图片跟Gif动图");
                    return;
                }
            }
            boolean added = !ImagePreSelectorActivity.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId));
            if (!added || ImagePreSelectorActivity.this.maxSelectedPhotos < 0 || ImagePreSelectorActivity.selectedPhotos.size() < ImagePreSelectorActivity.this.maxSelectedPhotos) {
                int num = added ? ImagePreSelectorActivity.selectedPhotosOrder.size() : -1;
                if (ImagePreSelectorActivity.this.allowOrder) {
                    v.setChecked(num, added, true);
                } else {
                    v.setChecked(-1, added, true);
                }
                ImagePreSelectorActivity.this.addToSelectedPhotos(photoEntry, index);
                int updateIndex = index;
                if (this == ImagePreSelectorActivity.this.cameraAttachAdapter) {
                    if (ImagePreSelectorActivity.this.adapter.needCamera && ImagePreSelectorActivity.this.selectedAlbumEntry == ImagePreSelectorActivity.this.galleryAlbumEntry) {
                        updateIndex++;
                    }
                    ImagePreSelectorActivity.this.adapter.notifyItemChanged(updateIndex);
                } else {
                    ImagePreSelectorActivity.this.cameraAttachAdapter.notifyItemChanged(updateIndex);
                }
                ImagePreSelectorActivity.this.updatePhotosButton();
                return;
            }
            XDialog.Builder builder = new XDialog.Builder(this.mContext);
            builder.setTitle(LocaleController.getString("image_select_tip", R.string.image_select_tip));
            builder.setMessage(LocaleController.formatString("image_select_max_warn", R.string.image_select_max_warn, Integer.valueOf(ImagePreSelectorActivity.this.maxSelectedPhotos)));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            builder.show();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public MediaController.PhotoEntry getPhoto(int position) {
            if (this.needCamera && ImagePreSelectorActivity.this.selectedAlbumEntry == ImagePreSelectorActivity.this.galleryAlbumEntry) {
                position--;
            }
            return ImagePreSelectorActivity.this.getPhotoEntryAtPosition(position);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType != 1) {
                    if (itemViewType == 3) {
                        PhotoAttachPermissionCell cell = (PhotoAttachPermissionCell) holder.itemView;
                        cell.setItemSize(ImagePreSelectorActivity.this.itemSize);
                        cell.setType((this.needCamera && ImagePreSelectorActivity.this.noCameraPermissions && position == 0) ? 0 : 1);
                        return;
                    }
                    return;
                }
                PhotoAttachCameraCell cameraCell = (PhotoAttachCameraCell) holder.itemView;
                if (ImagePreSelectorActivity.this.cameraView != null && ImagePreSelectorActivity.this.cameraView.isInitied()) {
                    cameraCell.setVisibility(4);
                } else {
                    cameraCell.setVisibility(0);
                }
                cameraCell.setItemSize(ImagePreSelectorActivity.this.itemSize);
                return;
            }
            if (this.needCamera && ImagePreSelectorActivity.this.selectedAlbumEntry == ImagePreSelectorActivity.this.galleryAlbumEntry) {
                position--;
            }
            PhotoAttachPhotoCell cell2 = (PhotoAttachPhotoCell) holder.itemView;
            if (this == ImagePreSelectorActivity.this.adapter) {
                cell2.setItemSize(ImagePreSelectorActivity.this.itemSize);
            } else {
                cell2.setIsVertical(ImagePreSelectorActivity.this.cameraPhotoLayoutManager.getOrientation() == 1);
            }
            MediaController.PhotoEntry photoEntry = ImagePreSelectorActivity.this.getPhotoEntryAtPosition(position);
            cell2.setPhotoEntry(photoEntry, this.needCamera && ImagePreSelectorActivity.this.selectedAlbumEntry == ImagePreSelectorActivity.this.galleryAlbumEntry, position == getItemCount() - 1);
            cell2.setChecked(-1, ImagePreSelectorActivity.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId)), false);
            cell2.getImageView().setTag(Integer.valueOf(position));
            cell2.setTag(Integer.valueOf(position));
            if (photoEntry.isVideo) {
                cell2.getCheckBox().setVisibility(8);
            } else {
                cell2.getCheckBox().setVisibility(0);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            if (viewType == 0) {
                if (!this.viewsCache.isEmpty()) {
                    RecyclerListView.Holder holder = this.viewsCache.get(0);
                    this.viewsCache.remove(0);
                    return holder;
                }
                RecyclerListView.Holder holder2 = createHolder();
                return holder2;
            }
            if (viewType != 1) {
                if (viewType == 2) {
                    RecyclerListView.Holder holder3 = new RecyclerListView.Holder(new View(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.PhotoAttachAdapter.3
                        @Override // android.view.View
                        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                            super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(ImagePreSelectorActivity.this.gridExtraSpace, 1073741824));
                        }
                    });
                    return holder3;
                }
                RecyclerListView.Holder holder4 = new RecyclerListView.Holder(new PhotoAttachPermissionCell(this.mContext));
                return holder4;
            }
            PhotoAttachCameraCell cameraCell = new PhotoAttachCameraCell(this.mContext);
            if (Build.VERSION.SDK_INT >= 21) {
                cameraCell.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.PhotoAttachAdapter.2
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view, Outline outline) {
                        int rad = AndroidUtilities.dp(ImagePreSelectorActivity.this.cornerRadius * 8.0f);
                        outline.setRoundRect(0, 0, view.getMeasuredWidth() + rad, view.getMeasuredHeight() + rad, rad);
                    }
                });
                cameraCell.setClipToOutline(true);
            }
            RecyclerListView.Holder holder5 = new RecyclerListView.Holder(cameraCell);
            return holder5;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            if (holder.itemView instanceof PhotoAttachCameraCell) {
                PhotoAttachCameraCell cell = (PhotoAttachCameraCell) holder.itemView;
                cell.updateBitmap();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (!ImagePreSelectorActivity.this.mediaEnabled) {
                return 1;
            }
            int count = 0;
            if (this.needCamera && ImagePreSelectorActivity.this.selectedAlbumEntry == ImagePreSelectorActivity.this.galleryAlbumEntry) {
                count = 0 + 1;
            }
            if (ImagePreSelectorActivity.this.noGalleryPermissions && this == ImagePreSelectorActivity.this.adapter) {
                count++;
            }
            int count2 = count + ImagePreSelectorActivity.cameraPhotos.size();
            if (ImagePreSelectorActivity.this.selectedAlbumEntry != null) {
                count2 += ImagePreSelectorActivity.this.selectedAlbumEntry.photos.size();
            }
            if (this == ImagePreSelectorActivity.this.adapter) {
                count2++;
            }
            this.itemsCount = count2;
            return count2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (!ImagePreSelectorActivity.this.mediaEnabled) {
                return 2;
            }
            if (this.needCamera && position == 0 && ImagePreSelectorActivity.this.selectedAlbumEntry == ImagePreSelectorActivity.this.galleryAlbumEntry) {
                return ImagePreSelectorActivity.this.noCameraPermissions ? 3 : 1;
            }
            if (this == ImagePreSelectorActivity.this.adapter && position == this.itemsCount - 1) {
                return 2;
            }
            return ImagePreSelectorActivity.this.noGalleryPermissions ? 3 : 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
            if (this == ImagePreSelectorActivity.this.adapter) {
                ImagePreSelectorActivity.this.progressView.setVisibility((!(getItemCount() == 1 && ImagePreSelectorActivity.this.selectedAlbumEntry == null) && ImagePreSelectorActivity.this.mediaEnabled) ? 4 : 0);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    public void dismissInternal() {
        if (this.containerView != null) {
            this.containerView.setVisibility(4);
        }
        super.dismissInternal();
    }

    @Override // android.app.Dialog
    public void onBackPressed() {
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji != null && editTextEmoji.isPopupShowing()) {
            this.commentTextView.hidePopup(true);
        } else {
            super.onBackPressed();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    public void dismissWithButtonClick(int item) {
        super.dismissWithButtonClick(item);
        hideCamera((item == 0 || item == 2) ? false : true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithTouchOutside() {
        return !this.cameraOpened;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        if (this.cameraAnimationInProgress) {
            return;
        }
        if (this.cameraOpened) {
            closeCamera(true);
            return;
        }
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji != null) {
            AndroidUtilities.hideKeyboard(editTextEmoji.getEditText());
        }
        hideCamera(true);
        super.dismiss();
    }

    @Override // android.app.Dialog, android.view.KeyEvent.Callback
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (this.cameraOpened && (keyCode == 24 || keyCode == 25)) {
            this.shutterButton.getDelegate().shutterReleased();
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    public void setCurrentSelectMediaType(int currentSelectMediaType) {
        this.currentSelectMediaType = currentSelectMediaType;
    }

    public int getCurrentSelectMediaType() {
        return this.currentSelectMediaType;
    }

    public ArrayList<Object> getCameraPhotos() {
        return cameraPhotos;
    }

    public MediaController.AlbumEntry getSelectedAlbumEntry() {
        return this.selectedAlbumEntry;
    }

    public MediaController.AlbumEntry getGalleryAlbumEntry() {
        return this.galleryAlbumEntry;
    }

    public int getCurrentSelectedCount() {
        return this.currentSelectedCount;
    }
}
