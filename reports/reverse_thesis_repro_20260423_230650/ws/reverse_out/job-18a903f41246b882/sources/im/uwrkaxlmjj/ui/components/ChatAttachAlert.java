package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.hardware.Camera;
import android.os.Build;
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
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.messenger.camera.CameraController;
import im.uwrkaxlmjj.messenger.camera.CameraView;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuSubItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.PhotoAttachCameraCell;
import im.uwrkaxlmjj.ui.cells.PhotoAttachPermissionCell;
import im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AnimationProperties;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector;
import im.uwrkaxlmjj.ui.components.ShutterButton;
import im.uwrkaxlmjj.ui.components.ZoomControlView;
import im.uwrkaxlmjj.ui.hui.adapter.EditInputFilter;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class ChatAttachAlert extends BottomSheet implements NotificationCenter.NotificationCenterDelegate, BottomSheet.BottomSheetDelegateInterface {
    private static final int compress = 1;
    private static final int group = 0;
    private static boolean mediaFromExternalCamera;
    private final Property<ChatAttachAlert, Float> ATTACH_ALERT_PROGRESS;
    private ActionBar actionBar;
    private AnimatorSet actionBarAnimation;
    private View actionBarShadow;
    private PhotoAttachAdapter adapter;
    private int alertOnlyOnce;
    private boolean allowOrder;
    private int[] animateCameraValues;
    private AnimatorSet animatorSet;
    private int attachItemSize;
    private BaseFragment baseFragment;
    private boolean buttonPressed;
    private ButtonsAdapter buttonsAdapter;
    private LinearLayoutManager buttonsLayoutManager;
    private RecyclerListView buttonsRecyclerView;
    private boolean cameraAnimationInProgress;
    private PhotoAttachAdapter cameraAttachAdapter;
    private Drawable cameraDrawable;
    private FrameLayout cameraIcon;
    private AnimatorSet cameraInitAnimation;
    private boolean cameraInitied;
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
    private int currentSelectedCount;
    private DecelerateInterpolator decelerateInterpolator;
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
    private FrameLayout frameLayout2;
    private MediaController.AlbumEntry galleryAlbumEntry;
    private int gridExtraSpace;
    private RecyclerListView gridView;
    private android.graphics.Rect hitRect;
    private DecelerateInterpolator interpolator;
    private ActionBarMenuSubItem[] itemCells;
    private RecyclerViewItemRangeSelector itemRangeSelector;
    private int itemSize;
    private int itemsPerRow;
    private int lastItemSize;
    private float lastY;
    private GridLayoutManager layoutManager;
    private boolean loading;
    private int maxSelectedPhotos;
    private boolean maybeStartDraging;
    private boolean mediaCaptured;
    private boolean mediaEnabled;
    private AnimatorSet menuAnimator;
    private boolean menuShowed;
    private boolean noCameraPermissions;
    private boolean noGalleryPermissions;
    private boolean openWithFrontFaceCamera;
    private Paint paint;
    private boolean paused;
    private PhotoViewer.PhotoViewerProvider photoViewerProvider;
    private float pinchStartDistance;
    private boolean pollsEnabled;
    private boolean pressed;
    private EmptyTextProgressView progressView;
    private TextView recordTime;
    private RectF rect;
    private boolean requestingPermissions;
    private int scrollOffsetY;
    private MediaController.AlbumEntry selectedAlbumEntry;
    private View selectedCountView;
    private ActionBarMenuItem selectedMenuItem;
    private TextView selectedTextView;
    private ActionBarPopupWindow.ActionBarPopupWindowLayout sendPopupLayout;
    private ActionBarPopupWindow sendPopupWindow;
    private View shadow;
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

    static /* synthetic */ int access$8508(ChatAttachAlert x0) {
        int i = x0.videoRecordTime;
        x0.videoRecordTime = i + 1;
        return i;
    }

    static /* synthetic */ int access$9310() {
        int i = lastImageId;
        lastImageId = i - 1;
        return i;
    }

    private class InnerAnimator {
        private AnimatorSet animatorSet;
        private float startRadius;

        private InnerAnimator() {
        }
    }

    private class BasePhotoProvider extends PhotoViewer.EmptyPhotoViewerProvider {
        private BasePhotoProvider() {
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean isPhotoChecked(int index) {
            MediaController.PhotoEntry photoEntry = ChatAttachAlert.this.getPhotoEntryAtPosition(index);
            return photoEntry != null && ChatAttachAlert.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId));
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int setPhotoChecked(int index, VideoEditedInfo videoEditedInfo) {
            MediaController.PhotoEntry photoEntry;
            if ((ChatAttachAlert.this.maxSelectedPhotos >= 0 && ChatAttachAlert.selectedPhotos.size() >= ChatAttachAlert.this.maxSelectedPhotos && !isPhotoChecked(index)) || (photoEntry = ChatAttachAlert.this.getPhotoEntryAtPosition(index)) == null) {
                return -1;
            }
            boolean add = true;
            int iAddToSelectedPhotos = ChatAttachAlert.this.addToSelectedPhotos(photoEntry, -1);
            int num = iAddToSelectedPhotos;
            if (iAddToSelectedPhotos == -1) {
                num = ChatAttachAlert.selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry.imageId));
            } else {
                add = false;
                photoEntry.editedInfo = null;
            }
            photoEntry.editedInfo = videoEditedInfo;
            int count = ChatAttachAlert.this.gridView.getChildCount();
            int a = 0;
            while (true) {
                if (a >= count) {
                    break;
                }
                View view = ChatAttachAlert.this.gridView.getChildAt(a);
                if (view instanceof PhotoAttachPhotoCell) {
                    int tag = ((Integer) view.getTag()).intValue();
                    if (tag == index) {
                        if ((ChatAttachAlert.this.baseFragment instanceof ChatActivity) && ChatAttachAlert.this.allowOrder) {
                            ((PhotoAttachPhotoCell) view).setChecked(num, add, false);
                        } else {
                            ((PhotoAttachPhotoCell) view).setChecked(-1, add, false);
                        }
                    }
                }
                a++;
            }
            int count2 = ChatAttachAlert.this.cameraPhotoRecyclerView.getChildCount();
            int a2 = 0;
            while (true) {
                if (a2 >= count2) {
                    break;
                }
                View view2 = ChatAttachAlert.this.cameraPhotoRecyclerView.getChildAt(a2);
                if (view2 instanceof PhotoAttachPhotoCell) {
                    int tag2 = ((Integer) view2.getTag()).intValue();
                    if (tag2 == index) {
                        if ((ChatAttachAlert.this.baseFragment instanceof ChatActivity) && ChatAttachAlert.this.allowOrder) {
                            ((PhotoAttachPhotoCell) view2).setChecked(num, add, false);
                        } else {
                            ((PhotoAttachPhotoCell) view2).setChecked(-1, add, false);
                        }
                    }
                }
                a2++;
            }
            ChatAttachAlert.this.updatePhotosButton(add ? 1 : 2);
            return num;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int getSelectedCount() {
            return ChatAttachAlert.selectedPhotos.size();
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public ArrayList<Object> getSelectedPhotosOrder() {
            return ChatAttachAlert.selectedPhotosOrder;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public HashMap<Object, Object> getSelectedPhotos() {
            return ChatAttachAlert.selectedPhotos;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int getPhotoIndex(int index) {
            MediaController.PhotoEntry photoEntry = ChatAttachAlert.this.getPhotoEntryAtPosition(index);
            if (photoEntry != null) {
                return ChatAttachAlert.selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry.imageId));
            }
            return -1;
        }
    }

    private void updateCheckedPhotoIndices() {
        if (!(this.baseFragment instanceof ChatActivity)) {
            return;
        }
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

    private class AttachButton extends FrameLayout {
        private ImageView imageView;
        private TextView textView;

        public AttachButton(Context context) {
            super(context);
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            if (Build.VERSION.SDK_INT >= 21) {
                this.imageView.setImageDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 1, AndroidUtilities.dp(25.0f)));
            }
            addView(this.imageView, LayoutHelper.createFrame(50.0f, 50.0f, 49, 0.0f, 12.0f, 0.0f, 0.0f));
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setMaxLines(2);
            this.textView.setGravity(1);
            this.textView.setEllipsize(TextUtils.TruncateAt.END);
            this.textView.setTextColor(Theme.getColor(Theme.key_dialogTextGray2));
            this.textView.setTextSize(1, 12.0f);
            this.textView.setLineSpacing(-AndroidUtilities.dp(2.0f), 1.0f);
            addView(this.textView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 0.0f, 66.0f, 0.0f, 0.0f));
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(ChatAttachAlert.this.attachItemSize, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(92.0f), 1073741824));
        }

        public void setTextAndIcon(CharSequence text, Drawable drawable) {
            this.textView.setText(text);
            this.imageView.setBackgroundDrawable(drawable);
        }

        @Override // android.view.View
        public boolean hasOverlappingRendering() {
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class AttachBotButton extends FrameLayout {
        private AvatarDrawable avatarDrawable;
        private TLRPC.User currentUser;
        private BackupImageView imageView;
        private TextView nameTextView;

        public AttachBotButton(Context context) {
            super(context);
            this.avatarDrawable = new AvatarDrawable();
            BackupImageView backupImageView = new BackupImageView(context);
            this.imageView = backupImageView;
            backupImageView.setRoundRadius(AndroidUtilities.dp(25.0f));
            addView(this.imageView, LayoutHelper.createFrame(50.0f, 50.0f, 49, 0.0f, 12.0f, 0.0f, 0.0f));
            if (Build.VERSION.SDK_INT >= 21) {
                View selector = new View(context);
                selector.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 1, AndroidUtilities.dp(25.0f)));
                addView(selector, LayoutHelper.createFrame(50.0f, 50.0f, 49, 0.0f, 12.0f, 0.0f, 0.0f));
            }
            TextView textView = new TextView(context);
            this.nameTextView = textView;
            textView.setTextSize(1, 12.0f);
            this.nameTextView.setGravity(49);
            this.nameTextView.setLines(1);
            this.nameTextView.setSingleLine(true);
            this.nameTextView.setEllipsize(TextUtils.TruncateAt.END);
            addView(this.nameTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 6.0f, 66.0f, 6.0f, 0.0f));
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(ChatAttachAlert.this.attachItemSize, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(100.0f), 1073741824));
        }

        public void setUser(TLRPC.User user) {
            if (user == null) {
                return;
            }
            this.nameTextView.setTextColor(Theme.getColor(Theme.key_dialogTextGray2));
            this.currentUser = user;
            this.nameTextView.setText(ContactsController.formatName(user.first_name, user.last_name));
            this.avatarDrawable.setInfo(user);
            this.imageView.setImage(ImageLocation.getForUser(user, false), "50_50", this.avatarDrawable, user);
            requestLayout();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public ChatAttachAlert(Context context, final BaseFragment baseFragment) {
        super(context, false, 1);
        int i = 0;
        Object[] objArr = 0;
        this.textPaint = new TextPaint(1);
        this.rect = new RectF();
        this.paint = new Paint(1);
        this.cornerRadius = 1.0f;
        this.currentAccount = UserConfig.selectedAccount;
        this.mediaEnabled = true;
        this.pollsEnabled = true;
        this.flashModeButton = new ImageView[2];
        this.cameraViewLocation = new int[2];
        this.viewPosition = new int[2];
        this.animateCameraValues = new int[5];
        this.interpolator = new DecelerateInterpolator(1.5f);
        this.maxSelectedPhotos = -1;
        this.allowOrder = true;
        this.hitRect = new android.graphics.Rect();
        int iDp = AndroidUtilities.dp(80.0f);
        this.itemSize = iDp;
        this.lastItemSize = iDp;
        this.attachItemSize = AndroidUtilities.dp(85.0f);
        this.itemsPerRow = 3;
        this.decelerateInterpolator = new DecelerateInterpolator();
        this.loading = true;
        this.photoViewerProvider = new BasePhotoProvider() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.1
            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
                PhotoAttachPhotoCell cell = ChatAttachAlert.this.getCellForIndex(index);
                if (cell != null) {
                    int[] coords = new int[2];
                    cell.getImageView().getLocationInWindow(coords);
                    if (Build.VERSION.SDK_INT < 26) {
                        coords[0] = coords[0] - ChatAttachAlert.this.getLeftInset();
                    }
                    PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
                    object.viewX = coords[0];
                    object.viewY = coords[1];
                    object.parentView = ChatAttachAlert.this.gridView;
                    object.imageReceiver = cell.getImageView().getImageReceiver();
                    object.thumb = object.imageReceiver.getBitmapSafe();
                    object.scale = cell.getScale();
                    cell.showCheck(false);
                    return object;
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public void updatePhotoAtIndex(int index) {
                PhotoAttachPhotoCell cell = ChatAttachAlert.this.getCellForIndex(index);
                if (cell != null) {
                    cell.getImageView().setOrientation(0, true);
                    MediaController.PhotoEntry photoEntry = ChatAttachAlert.this.getPhotoEntryAtPosition(index);
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

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public ImageReceiver.BitmapHolder getThumbForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
                PhotoAttachPhotoCell cell = ChatAttachAlert.this.getCellForIndex(index);
                if (cell != null) {
                    return cell.getImageView().getImageReceiver().getBitmapSafe();
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public void willSwitchFromPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
                PhotoAttachPhotoCell cell = ChatAttachAlert.this.getCellForIndex(index);
                if (cell != null) {
                    cell.showCheck(true);
                }
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public void willHidePhotoViewer() {
                int count = ChatAttachAlert.this.gridView.getChildCount();
                for (int a = 0; a < count; a++) {
                    View view = ChatAttachAlert.this.gridView.getChildAt(a);
                    if (view instanceof PhotoAttachPhotoCell) {
                        PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                        cell.showCheck(true);
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public boolean cancelButtonPressed() {
                return false;
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
                MediaController.PhotoEntry photoEntry = ChatAttachAlert.this.getPhotoEntryAtPosition(index);
                if (photoEntry != null) {
                    photoEntry.editedInfo = videoEditedInfo;
                }
                if (ChatAttachAlert.selectedPhotos.isEmpty() && photoEntry != null) {
                    ChatAttachAlert.this.addToSelectedPhotos(photoEntry, -1);
                }
                ChatAttachAlert.this.applyCaption();
                ChatAttachAlert.this.delegate.didPressedButton(7, true, notify, scheduleDate);
            }
        };
        this.ATTACH_ALERT_PROGRESS = new AnimationProperties.FloatProperty<ChatAttachAlert>("openProgress") { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.23
            private float openProgress;

            @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.FloatProperty
            public void setValue(ChatAttachAlert object, float value) {
                float scale;
                int N = ChatAttachAlert.this.buttonsRecyclerView.getChildCount();
                for (int a = 0; a < N; a++) {
                    float startTime = (3 - a) * 32.0f;
                    View child = ChatAttachAlert.this.buttonsRecyclerView.getChildAt(a);
                    if (value > startTime) {
                        float elapsedTime = value - startTime;
                        if (elapsedTime <= 200.0f) {
                            scale = CubicBezierInterpolator.EASE_OUT.getInterpolation(elapsedTime / 200.0f) * 1.1f;
                            child.setAlpha(CubicBezierInterpolator.EASE_BOTH.getInterpolation(elapsedTime / 200.0f));
                        } else {
                            child.setAlpha(1.0f);
                            float elapsedTime2 = elapsedTime - 200.0f;
                            scale = elapsedTime2 <= 100.0f ? 1.1f - (CubicBezierInterpolator.EASE_IN.getInterpolation(elapsedTime2 / 100.0f) * 0.1f) : 1.0f;
                        }
                    } else {
                        scale = 0.0f;
                    }
                    if (child instanceof AttachButton) {
                        AttachButton attachButton = (AttachButton) child;
                        attachButton.textView.setScaleX(scale);
                        attachButton.textView.setScaleY(scale);
                        attachButton.imageView.setScaleX(scale);
                        attachButton.imageView.setScaleY(scale);
                    } else if (child instanceof AttachBotButton) {
                        AttachBotButton attachButton2 = (AttachBotButton) child;
                        attachButton2.nameTextView.setScaleX(scale);
                        attachButton2.nameTextView.setScaleY(scale);
                        attachButton2.imageView.setScaleX(scale);
                        attachButton2.imageView.setScaleY(scale);
                    }
                }
            }

            @Override // android.util.Property
            public Float get(ChatAttachAlert object) {
                return Float.valueOf(this.openProgress);
            }
        };
        this.openInterpolator = new OvershootInterpolator(0.7f);
        this.baseFragment = baseFragment;
        setDelegate(this);
        checkCamera(false);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.albumsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.reloadInlineHints);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.cameraInitied);
        this.cameraDrawable = context.getResources().getDrawable(R.drawable.instant_camera).mutate();
        AnonymousClass2 anonymousClass2 = new AnonymousClass2(context);
        this.sizeNotifierFrameLayout = anonymousClass2;
        this.containerView = anonymousClass2;
        this.containerView.setWillNotDraw(false);
        this.containerView.setPadding(this.backgroundPaddingLeft, 0, this.backgroundPaddingLeft, 0);
        TextView textView = new TextView(context);
        this.selectedTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.selectedTextView.setTextSize(1, 16.0f);
        this.selectedTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.selectedTextView.setGravity(51);
        this.selectedTextView.setVisibility(4);
        this.selectedTextView.setAlpha(0.0f);
        this.containerView.addView(this.selectedTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 23.0f, 0.0f, 48.0f, 0.0f));
        ActionBar actionBar = new ActionBar(context) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.3
            @Override // android.view.View
            public void setAlpha(float alpha) {
                super.setAlpha(alpha);
                ChatAttachAlert.this.containerView.invalidate();
                if (ChatAttachAlert.this.frameLayout2 != null && ChatAttachAlert.this.buttonsRecyclerView != null) {
                    if (ChatAttachAlert.this.frameLayout2.getTag() == null) {
                        ChatAttachAlert.this.buttonsRecyclerView.setAlpha(1.0f - alpha);
                        ChatAttachAlert.this.shadow.setAlpha(1.0f - alpha);
                        ChatAttachAlert.this.buttonsRecyclerView.setTranslationY(AndroidUtilities.dp(44.0f) * alpha);
                        ChatAttachAlert.this.frameLayout2.setTranslationY(AndroidUtilities.dp(48.0f) * alpha);
                        ChatAttachAlert.this.shadow.setTranslationY(AndroidUtilities.dp(92.0f) * alpha);
                        return;
                    }
                    float value = alpha != 0.0f ? 0.0f : 1.0f;
                    if (ChatAttachAlert.this.buttonsRecyclerView.getAlpha() != value) {
                        ChatAttachAlert.this.buttonsRecyclerView.setAlpha(value);
                    }
                }
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
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass4(baseFragment));
        ActionBarMenuItem actionBarMenuItem = new ActionBarMenuItem(context, null, 0, Theme.getColor(Theme.key_dialogTextBlack)) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.5
            @Override // android.view.View
            public void setAlpha(float alpha) {
                super.setAlpha(alpha);
                ChatAttachAlert.this.updateSelectedPosition();
                ChatAttachAlert.this.containerView.invalidate();
            }
        };
        this.selectedMenuItem = actionBarMenuItem;
        actionBarMenuItem.setLongClickEnabled(false);
        this.selectedMenuItem.setIcon(R.drawable.ic_ab_other);
        this.selectedMenuItem.setContentDescription(LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
        this.selectedMenuItem.addSubItem(0, LocaleController.getString("SendWithoutGrouping", R.string.SendWithoutGrouping));
        this.selectedMenuItem.addSubItem(1, LocaleController.getString("SendWithoutCompression", R.string.SendWithoutCompression));
        this.selectedMenuItem.setVisibility(4);
        this.selectedMenuItem.setAlpha(0.0f);
        this.selectedMenuItem.setSubMenuOpenSide(2);
        this.selectedMenuItem.setDelegate(new ActionBarMenuItem.ActionBarMenuItemDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$mLSwV2bQ1S-rIDh_gJvG2NRHU_4
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemDelegate
            public final void onItemClick(int i2) {
                this.f$0.lambda$new$0$ChatAttachAlert(i2);
            }
        });
        this.selectedMenuItem.setAdditionalYOffset(AndroidUtilities.dp(72.0f));
        this.selectedMenuItem.setTranslationX(AndroidUtilities.dp(6.0f));
        this.selectedMenuItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 6));
        this.containerView.addView(this.selectedMenuItem, LayoutHelper.createFrame(48, 48, 53));
        this.selectedMenuItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$BbrS77ZFOnXjLV1WMW6NmHwSvOY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$1$ChatAttachAlert(view);
            }
        });
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.6
            @Override // android.view.View
            public void setTranslationY(float translationY) {
                super.setTranslationY(translationY);
                ChatAttachAlert.this.containerView.invalidate();
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public boolean onTouchEvent(MotionEvent e) {
                if (e.getAction() == 0 && e.getY() < ChatAttachAlert.this.scrollOffsetY - AndroidUtilities.dp(44.0f)) {
                    return false;
                }
                return super.onTouchEvent(e);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent e) {
                if (e.getAction() == 0 && e.getY() < ChatAttachAlert.this.scrollOffsetY - AndroidUtilities.dp(44.0f)) {
                    return false;
                }
                return super.onInterceptTouchEvent(e);
            }
        };
        this.gridView = recyclerListView;
        PhotoAttachAdapter photoAttachAdapter = new PhotoAttachAdapter(context, true);
        this.adapter = photoAttachAdapter;
        recyclerListView.setAdapter(photoAttachAdapter);
        this.gridView.setClipToPadding(false);
        this.gridView.setItemAnimator(null);
        this.gridView.setLayoutAnimation(null);
        this.gridView.setVerticalScrollBarEnabled(false);
        this.gridView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        this.containerView.addView(this.gridView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 11.0f, 0.0f, 0.0f));
        this.gridView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.7
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                if (ChatAttachAlert.this.gridView.getChildCount() > 0) {
                    ChatAttachAlert.this.updateLayout(true);
                    ChatAttachAlert.this.checkCameraViewPosition();
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 0) {
                    int offset = AndroidUtilities.dp(13.0f) + (ChatAttachAlert.this.selectedMenuItem != null ? AndroidUtilities.dp(ChatAttachAlert.this.selectedMenuItem.getAlpha() * 26.0f) : 0);
                    int top = (ChatAttachAlert.this.scrollOffsetY - ChatAttachAlert.this.backgroundPaddingTop) - offset;
                    if (ChatAttachAlert.this.backgroundPaddingTop + top < ActionBar.getCurrentActionBarHeight()) {
                        ChatAttachAlert.this.gridView.getChildAt(0);
                        RecyclerListView.Holder holder = (RecyclerListView.Holder) ChatAttachAlert.this.gridView.findViewHolderForAdapterPosition(0);
                        if (holder != null && holder.itemView.getTop() > AndroidUtilities.dp(7.0f)) {
                            ChatAttachAlert.this.gridView.smoothScrollBy(0, holder.itemView.getTop() - AndroidUtilities.dp(7.0f));
                        }
                    }
                }
            }
        });
        GridLayoutManager gridLayoutManager = new GridLayoutManager(context, this.itemSize) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.8
            @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = gridLayoutManager;
        gridLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.9
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                if (position == ChatAttachAlert.this.adapter.itemsCount - 1) {
                    return ChatAttachAlert.this.layoutManager.getSpanCount();
                }
                return ChatAttachAlert.this.itemSize + (position % ChatAttachAlert.this.itemsPerRow != ChatAttachAlert.this.itemsPerRow + (-1) ? AndroidUtilities.dp(5.0f) : 0);
            }
        });
        this.gridView.setLayoutManager(this.layoutManager);
        this.gridView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$vqRp51TrrrF3Ssdo0Z2l36P-nWI
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i2) {
                this.f$0.lambda$new$2$ChatAttachAlert(view, i2);
            }
        });
        this.gridView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$gC64ea6ziBSexoTFbuJ4YcupEis
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i2) {
                return this.f$0.lambda$new$3$ChatAttachAlert(view, i2);
            }
        });
        RecyclerViewItemRangeSelector recyclerViewItemRangeSelector = new RecyclerViewItemRangeSelector(new RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.10
            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public int getItemCount() {
                return ChatAttachAlert.this.adapter.getItemCount();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public void setSelected(View view, int index, boolean selected) {
                if (selected != ChatAttachAlert.this.shouldSelect || !(view instanceof PhotoAttachPhotoCell)) {
                    return;
                }
                PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                cell.callDelegate();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public boolean isSelected(int index) {
                MediaController.PhotoEntry entry = ChatAttachAlert.this.adapter.getPhoto(index);
                return entry != null && ChatAttachAlert.selectedPhotos.containsKey(Integer.valueOf(entry.imageId));
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public boolean isIndexSelectable(int index) {
                return ChatAttachAlert.this.adapter.getItemViewType(index) == 0;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public void onStartStopSelection(boolean z) {
                ChatAttachAlert.this.alertOnlyOnce = z ? 1 : 0;
                ChatAttachAlert.this.gridView.hideSelector();
            }
        });
        this.itemRangeSelector = recyclerViewItemRangeSelector;
        this.gridView.addOnItemTouchListener(recyclerViewItemRangeSelector);
        ActionBarMenuItem actionBarMenuItem2 = new ActionBarMenuItem(context, this.actionBar.createMenu(), 0, 0);
        this.dropDownContainer = actionBarMenuItem2;
        actionBarMenuItem2.setSubMenuOpenSide(1);
        this.actionBar.addView(this.dropDownContainer, 0, LayoutHelper.createFrame(-2.0f, -1.0f, 51, AndroidUtilities.isTablet() ? 64.0f : 56.0f, 0.0f, 40.0f, 0.0f));
        this.dropDownContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$TZqTziV7qNubyW7QwyyyrQmP9nE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$4$ChatAttachAlert(view);
            }
        });
        TextView textView2 = new TextView(context);
        this.dropDown = textView2;
        textView2.setGravity(3);
        this.dropDown.setSingleLine(true);
        this.dropDown.setLines(1);
        this.dropDown.setMaxLines(1);
        this.dropDown.setEllipsize(TextUtils.TruncateAt.END);
        this.dropDown.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.dropDown.setText(LocaleController.getString("ChatGallery", R.string.ChatGallery));
        this.dropDown.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        Drawable drawableMutate = context.getResources().getDrawable(R.drawable.ic_arrow_drop_down).mutate();
        this.dropDownDrawable = drawableMutate;
        drawableMutate.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogTextBlack), PorterDuff.Mode.MULTIPLY));
        this.dropDown.setCompoundDrawablePadding(AndroidUtilities.dp(4.0f));
        this.dropDown.setPadding(0, 0, AndroidUtilities.dp(10.0f), 0);
        this.dropDownContainer.addView(this.dropDown, LayoutHelper.createFrame(-2.0f, -2.0f, 16, 16.0f, 0.0f, 0.0f, 0.0f));
        View view = new View(context);
        this.actionBarShadow = view;
        view.setAlpha(0.0f);
        this.actionBarShadow.setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        this.containerView.addView(this.actionBarShadow, LayoutHelper.createFrame(-1, 1.0f));
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
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
        View view2 = new View(context);
        this.shadow = view2;
        view2.setBackgroundResource(R.drawable.header_shadow_reverse);
        this.containerView.addView(this.shadow, LayoutHelper.createFrame(-1.0f, 3.0f, 83, 0.0f, 0.0f, 0.0f, 92.0f));
        RecyclerListView recyclerListView2 = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.11
            @Override // android.view.View
            public void setTranslationY(float translationY) {
                super.setTranslationY(translationY);
                ChatAttachAlert.this.checkCameraViewPosition();
            }
        };
        this.buttonsRecyclerView = recyclerListView2;
        ButtonsAdapter buttonsAdapter = new ButtonsAdapter(context);
        this.buttonsAdapter = buttonsAdapter;
        recyclerListView2.setAdapter(buttonsAdapter);
        RecyclerListView recyclerListView3 = this.buttonsRecyclerView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 0, false);
        this.buttonsLayoutManager = linearLayoutManager;
        recyclerListView3.setLayoutManager(linearLayoutManager);
        this.buttonsRecyclerView.setVerticalScrollBarEnabled(false);
        this.buttonsRecyclerView.setHorizontalScrollBarEnabled(false);
        this.buttonsRecyclerView.setItemAnimator(null);
        this.buttonsRecyclerView.setLayoutAnimation(null);
        this.buttonsRecyclerView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        this.buttonsRecyclerView.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.containerView.addView(this.buttonsRecyclerView, LayoutHelper.createFrame(-1, 92, 83));
        this.buttonsRecyclerView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$iOzMk1S7j81M18MqZrRVLWoX5D4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view3, int i2) {
                this.f$0.lambda$new$5$ChatAttachAlert(view3, i2);
            }
        });
        this.buttonsRecyclerView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$Hw2auTtDctMvU_O-C9fhenwPfM8
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view3, int i2) {
                return this.f$0.lambda$new$7$ChatAttachAlert(view3, i2);
            }
        });
        FrameLayout frameLayout = new FrameLayout(context);
        this.frameLayout2 = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.frameLayout2.setVisibility(4);
        this.frameLayout2.setAlpha(0.0f);
        this.containerView.addView(this.frameLayout2, LayoutHelper.createFrame(-1, 48, 83));
        this.frameLayout2.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$L4AT0yiWShpI10EAxw9S_97cGtM
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view3, MotionEvent motionEvent) {
                return ChatAttachAlert.lambda$new$8(view3, motionEvent);
            }
        });
        this.commentTextView = new AnonymousClass12(context, this.sizeNotifierFrameLayout, null, 1);
        this.commentTextView.setFilters(new InputFilter[]{new InputFilter.LengthFilter(MessagesController.getInstance(UserConfig.selectedAccount).maxCaptionLength)});
        this.commentTextView.setHint(LocaleController.getString("AddCaption", R.string.AddCaption));
        this.commentTextView.onResume();
        EditTextBoldCursor editText = this.commentTextView.getEditText();
        editText.setMaxLines(1);
        editText.setSingleLine(true);
        this.frameLayout2.addView(this.commentTextView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 84.0f, 0.0f));
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.writeButtonContainer = frameLayout2;
        frameLayout2.setVisibility(4);
        this.writeButtonContainer.setScaleX(0.2f);
        this.writeButtonContainer.setScaleY(0.2f);
        this.writeButtonContainer.setAlpha(0.0f);
        this.writeButtonContainer.setContentDescription(LocaleController.getString("Send", R.string.Send));
        this.containerView.addView(this.writeButtonContainer, LayoutHelper.createFrame(60.0f, 60.0f, 85, 0.0f, 0.0f, 6.0f, 10.0f));
        this.writeButtonContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$YBRB-SnFJOppFfwChuTZYcJMs6c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$new$9$ChatAttachAlert(baseFragment, view3);
            }
        });
        this.writeButtonContainer.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$DRUvXsZ5x9S7yJHmgBC0pV8Bp9Q
            @Override // android.view.View.OnLongClickListener
            public final boolean onLongClick(View view3) {
                return this.f$0.lambda$new$12$ChatAttachAlert(view3);
            }
        });
        this.writeButton = new ImageView(context);
        this.writeButtonDrawable = Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), Theme.getColor(Theme.key_dialogFloatingButton), Theme.getColor(Theme.key_dialogFloatingButtonPressed));
        if (Build.VERSION.SDK_INT < 21) {
            Drawable drawableMutate2 = context.getResources().getDrawable(R.drawable.floating_shadow_profile).mutate();
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
            this.writeButton.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.14
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view3, Outline outline) {
                    outline.setOval(0, 0, AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
                }
            });
        }
        this.writeButtonContainer.addView(this.writeButton, LayoutHelper.createFrame(Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, 51, Build.VERSION.SDK_INT >= 21 ? 2.0f : 0.0f, 0.0f, 0.0f, 0.0f));
        this.textPaint.setTextSize(AndroidUtilities.dp(12.0f));
        this.textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        View view3 = new View(context) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.15
            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                String text = String.format("%d", Integer.valueOf(Math.max(1, ChatAttachAlert.selectedPhotosOrder.size())));
                int textSize = (int) Math.ceil(ChatAttachAlert.this.textPaint.measureText(text));
                int size = Math.max(AndroidUtilities.dp(16.0f) + textSize, AndroidUtilities.dp(24.0f));
                int cx = getMeasuredWidth() / 2;
                int measuredHeight = getMeasuredHeight() / 2;
                ChatAttachAlert.this.textPaint.setColor(Theme.getColor(Theme.key_dialogRoundCheckBoxCheck));
                ChatAttachAlert.this.paint.setColor(Theme.getColor(Theme.key_dialogBackground));
                ChatAttachAlert.this.rect.set(cx - (size / 2), 0.0f, (size / 2) + cx, getMeasuredHeight());
                canvas.drawRoundRect(ChatAttachAlert.this.rect, AndroidUtilities.dp(12.0f), AndroidUtilities.dp(12.0f), ChatAttachAlert.this.paint);
                ChatAttachAlert.this.paint.setColor(Theme.getColor(Theme.key_dialogRoundCheckBox));
                ChatAttachAlert.this.rect.set((cx - (size / 2)) + AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), ((size / 2) + cx) - AndroidUtilities.dp(2.0f), getMeasuredHeight() - AndroidUtilities.dp(2.0f));
                canvas.drawRoundRect(ChatAttachAlert.this.rect, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), ChatAttachAlert.this.paint);
                canvas.drawText(text, cx - (textSize / 2), AndroidUtilities.dp(16.2f), ChatAttachAlert.this.textPaint);
            }
        };
        this.selectedCountView = view3;
        view3.setAlpha(0.0f);
        this.selectedCountView.setScaleX(0.2f);
        this.selectedCountView.setScaleY(0.2f);
        this.containerView.addView(this.selectedCountView, LayoutHelper.createFrame(42.0f, 24.0f, 85, 0.0f, 0.0f, -8.0f, 9.0f));
        TextView textView3 = new TextView(context);
        this.recordTime = textView3;
        textView3.setBackgroundResource(R.drawable.system);
        this.recordTime.getBackground().setColorFilter(new PorterDuffColorFilter(1711276032, PorterDuff.Mode.MULTIPLY));
        this.recordTime.setTextSize(1, 15.0f);
        this.recordTime.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.recordTime.setAlpha(0.0f);
        this.recordTime.setTextColor(-1);
        this.recordTime.setPadding(AndroidUtilities.dp(10.0f), AndroidUtilities.dp(5.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(5.0f));
        this.container.addView(this.recordTime, LayoutHelper.createFrame(-2.0f, -2.0f, 49, 0.0f, 16.0f, 0.0f, 0.0f));
        FrameLayout frameLayout3 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.16
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
                int y = (cx32 - ChatAttachAlert.this.tooltipTextView.getMeasuredHeight()) - AndroidUtilities.dp(12.0f);
                if (getMeasuredWidth() == AndroidUtilities.dp(126.0f)) {
                    ChatAttachAlert.this.tooltipTextView.layout(cx - (ChatAttachAlert.this.tooltipTextView.getMeasuredWidth() / 2), getMeasuredHeight(), (ChatAttachAlert.this.tooltipTextView.getMeasuredWidth() / 2) + cx, getMeasuredHeight() + ChatAttachAlert.this.tooltipTextView.getMeasuredHeight());
                } else {
                    ChatAttachAlert.this.tooltipTextView.layout(cx - (ChatAttachAlert.this.tooltipTextView.getMeasuredWidth() / 2), y, (ChatAttachAlert.this.tooltipTextView.getMeasuredWidth() / 2) + cx, ChatAttachAlert.this.tooltipTextView.getMeasuredHeight() + y);
                }
                ChatAttachAlert.this.shutterButton.layout(cx - (ChatAttachAlert.this.shutterButton.getMeasuredWidth() / 2), cy - (ChatAttachAlert.this.shutterButton.getMeasuredHeight() / 2), (ChatAttachAlert.this.shutterButton.getMeasuredWidth() / 2) + cx, (ChatAttachAlert.this.shutterButton.getMeasuredHeight() / 2) + cy);
                ChatAttachAlert.this.switchCameraButton.layout(cx2 - (ChatAttachAlert.this.switchCameraButton.getMeasuredWidth() / 2), cy2 - (ChatAttachAlert.this.switchCameraButton.getMeasuredHeight() / 2), (ChatAttachAlert.this.switchCameraButton.getMeasuredWidth() / 2) + cx2, (ChatAttachAlert.this.switchCameraButton.getMeasuredHeight() / 2) + cy2);
                for (int a = 0; a < 2; a++) {
                    ChatAttachAlert.this.flashModeButton[a].layout(cy22 - (ChatAttachAlert.this.flashModeButton[a].getMeasuredWidth() / 2), cy3 - (ChatAttachAlert.this.flashModeButton[a].getMeasuredHeight() / 2), (ChatAttachAlert.this.flashModeButton[a].getMeasuredWidth() / 2) + cy22, (ChatAttachAlert.this.flashModeButton[a].getMeasuredHeight() / 2) + cy3);
                }
            }
        };
        this.cameraPanel = frameLayout3;
        frameLayout3.setVisibility(8);
        this.cameraPanel.setAlpha(0.0f);
        this.container.addView(this.cameraPanel, LayoutHelper.createFrame(-1, 126, 83));
        TextView textView4 = new TextView(context);
        this.counterTextView = textView4;
        textView4.setBackgroundResource(R.drawable.photos_rounded);
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
        this.counterTextView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$jT-TjTQ0oVNhrG5qnsg0cHwO2_c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view4) {
                this.f$0.lambda$new$13$ChatAttachAlert(view4);
            }
        });
        ZoomControlView zoomControlView = new ZoomControlView(context);
        this.zoomControlView = zoomControlView;
        zoomControlView.setVisibility(8);
        this.zoomControlView.setAlpha(0.0f);
        this.container.addView(this.zoomControlView, LayoutHelper.createFrame(-2.0f, 50.0f, 51, 0.0f, 0.0f, 0.0f, 116.0f));
        this.zoomControlView.setDelegate(new ZoomControlView.ZoomControlViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$14tB3_CqHei61HM__1gYUOKb5Io
            @Override // im.uwrkaxlmjj.ui.components.ZoomControlView.ZoomControlViewDelegate
            public final void didSetZoom(float f) {
                this.f$0.lambda$new$14$ChatAttachAlert(f);
            }
        });
        ShutterButton shutterButton = new ShutterButton(context);
        this.shutterButton = shutterButton;
        this.cameraPanel.addView(shutterButton, LayoutHelper.createFrame(84, 84, 17));
        this.shutterButton.setDelegate(new AnonymousClass17(baseFragment));
        this.shutterButton.setFocusable(true);
        this.shutterButton.setContentDescription(LocaleController.getString("AccDescrShutter", R.string.AccDescrShutter));
        ImageView imageView = new ImageView(context);
        this.switchCameraButton = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.cameraPanel.addView(this.switchCameraButton, LayoutHelper.createFrame(48, 48, 21));
        this.switchCameraButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$OaoSYuNJTm69mPQBHTtsvHbhqFc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view4) {
                this.f$0.lambda$new$15$ChatAttachAlert(view4);
            }
        });
        this.switchCameraButton.setContentDescription(LocaleController.getString("AccDescrSwitchCamera", R.string.AccDescrSwitchCamera));
        for (int i2 = 0; i2 < 2; i2++) {
            this.flashModeButton[i2] = new ImageView(context);
            this.flashModeButton[i2].setScaleType(ImageView.ScaleType.CENTER);
            this.flashModeButton[i2].setVisibility(4);
            this.cameraPanel.addView(this.flashModeButton[i2], LayoutHelper.createFrame(48, 48, 51));
            this.flashModeButton[i2].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$n3BCfIgE7ITCQ6BYxUTDpwwK8tc
                @Override // android.view.View.OnClickListener
                public final void onClick(View view4) {
                    this.f$0.lambda$new$16$ChatAttachAlert(view4);
                }
            });
            this.flashModeButton[i2].setContentDescription("flash mode " + i2);
        }
        TextView textView5 = new TextView(context);
        this.tooltipTextView = textView5;
        textView5.setTextSize(1, 15.0f);
        this.tooltipTextView.setTextColor(-1);
        this.tooltipTextView.setText(LocaleController.getString("TapForVideo", R.string.TapForVideo));
        this.tooltipTextView.setShadowLayer(AndroidUtilities.dp(3.33333f), 0.0f, AndroidUtilities.dp(0.666f), 1275068416);
        this.tooltipTextView.setPadding(AndroidUtilities.dp(6.0f), 0, AndroidUtilities.dp(6.0f), 0);
        this.cameraPanel.addView(this.tooltipTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 81, 0.0f, 0.0f, 0.0f, 16.0f));
        RecyclerListView recyclerListView4 = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.20
            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (ChatAttachAlert.this.cameraPhotoRecyclerViewIgnoreLayout) {
                    return;
                }
                super.requestLayout();
            }
        };
        this.cameraPhotoRecyclerView = recyclerListView4;
        recyclerListView4.setVerticalScrollBarEnabled(true);
        RecyclerListView recyclerListView5 = this.cameraPhotoRecyclerView;
        PhotoAttachAdapter photoAttachAdapter2 = new PhotoAttachAdapter(context, false);
        this.cameraAttachAdapter = photoAttachAdapter2;
        recyclerListView5.setAdapter(photoAttachAdapter2);
        this.cameraPhotoRecyclerView.setClipToPadding(false);
        this.cameraPhotoRecyclerView.setPadding(AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f), 0);
        this.cameraPhotoRecyclerView.setItemAnimator(null);
        this.cameraPhotoRecyclerView.setLayoutAnimation(null);
        this.cameraPhotoRecyclerView.setOverScrollMode(2);
        this.cameraPhotoRecyclerView.setVisibility(4);
        this.cameraPhotoRecyclerView.setAlpha(0.0f);
        this.container.addView(this.cameraPhotoRecyclerView, LayoutHelper.createFrame(-1, 80.0f));
        LinearLayoutManager linearLayoutManager2 = new LinearLayoutManager(context, i, objArr == true ? 1 : 0) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.21
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.cameraPhotoLayoutManager = linearLayoutManager2;
        this.cameraPhotoRecyclerView.setLayoutManager(linearLayoutManager2);
        this.cameraPhotoRecyclerView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$PqcLgpcvkNzU6m2DFiGiMssI6HM
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view4, int i3) {
                ChatAttachAlert.lambda$new$17(view4, i3);
            }
        });
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.ChatAttachAlert$2, reason: invalid class name */
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
            if (ChatAttachAlert.this.cameraAnimationInProgress) {
                return true;
            }
            if (ChatAttachAlert.this.cameraOpened) {
                return ChatAttachAlert.this.processTouchEvent(ev);
            }
            if (ev.getAction() == 0 && ChatAttachAlert.this.scrollOffsetY != 0 && ev.getY() < ChatAttachAlert.this.scrollOffsetY - AndroidUtilities.dp(36.0f) && ChatAttachAlert.this.actionBar.getAlpha() == 0.0f) {
                ChatAttachAlert.this.dismiss();
                return true;
            }
            return super.onInterceptTouchEvent(ev);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            if (ChatAttachAlert.this.cameraAnimationInProgress) {
                return true;
            }
            if (ChatAttachAlert.this.cameraOpened) {
                return ChatAttachAlert.this.processTouchEvent(event);
            }
            return !ChatAttachAlert.this.isDismissed() && super.onTouchEvent(event);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int padding;
            int totalHeight = View.MeasureSpec.getSize(heightMeasureSpec);
            if (Build.VERSION.SDK_INT >= 21) {
                this.ignoreLayout = true;
                setPadding(ChatAttachAlert.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight, ChatAttachAlert.this.backgroundPaddingLeft, 0);
                this.ignoreLayout = false;
            }
            int availableHeight = totalHeight - getPaddingTop();
            int keyboardSize = getKeyboardHeight();
            float f = 20.0f;
            if (!AndroidUtilities.isInMultiwindow && keyboardSize <= AndroidUtilities.dp(20.0f)) {
                availableHeight -= ChatAttachAlert.this.commentTextView.getEmojiPadding();
            }
            int availableWidth = View.MeasureSpec.getSize(widthMeasureSpec) - (ChatAttachAlert.this.backgroundPaddingLeft * 2);
            if (AndroidUtilities.isTablet()) {
                ChatAttachAlert.this.itemsPerRow = 4;
                ChatAttachAlert.this.selectedMenuItem.setAdditionalYOffset(-AndroidUtilities.dp(3.0f));
            } else if (AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y) {
                ChatAttachAlert.this.itemsPerRow = 4;
                ChatAttachAlert.this.selectedMenuItem.setAdditionalYOffset(0);
            } else {
                ChatAttachAlert.this.itemsPerRow = 3;
                ChatAttachAlert.this.selectedMenuItem.setAdditionalYOffset(-AndroidUtilities.dp(3.0f));
            }
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) ChatAttachAlert.this.gridView.getLayoutParams();
            layoutParams.topMargin = ActionBar.getCurrentActionBarHeight();
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) ChatAttachAlert.this.actionBarShadow.getLayoutParams();
            layoutParams2.topMargin = ActionBar.getCurrentActionBarHeight();
            this.ignoreLayout = true;
            ChatAttachAlert.this.itemSize = ((availableWidth - AndroidUtilities.dp(12.0f)) - AndroidUtilities.dp(10.0f)) / ChatAttachAlert.this.itemsPerRow;
            int newSize = availableWidth / Math.min(4, ChatAttachAlert.this.buttonsAdapter.getItemCount());
            if (ChatAttachAlert.this.attachItemSize != newSize) {
                ChatAttachAlert.this.attachItemSize = newSize;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$2$ckMfCHbtAzv3DwHxofsmzfy7Gmw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onMeasure$0$ChatAttachAlert$2();
                    }
                });
            }
            if (ChatAttachAlert.this.lastItemSize != ChatAttachAlert.this.itemSize) {
                ChatAttachAlert chatAttachAlert = ChatAttachAlert.this;
                chatAttachAlert.lastItemSize = chatAttachAlert.itemSize;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$2$mph_h_2HmJsuo90mfdWaiaBNRfU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onMeasure$1$ChatAttachAlert$2();
                    }
                });
            }
            TextView textView = ChatAttachAlert.this.dropDown;
            if (!AndroidUtilities.isTablet() && AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y) {
                f = 18.0f;
            }
            textView.setTextSize(f);
            ChatAttachAlert.this.layoutManager.setSpanCount((ChatAttachAlert.this.itemSize * ChatAttachAlert.this.itemsPerRow) + (AndroidUtilities.dp(5.0f) * (ChatAttachAlert.this.itemsPerRow - 1)));
            int rows = (int) Math.ceil((ChatAttachAlert.this.adapter.getItemCount() - 1) / ChatAttachAlert.this.itemsPerRow);
            int contentSize = (ChatAttachAlert.this.itemSize * rows) + ((rows - 1) * AndroidUtilities.dp(5.0f));
            int newSize2 = Math.max(0, ((availableHeight - contentSize) - ActionBar.getCurrentActionBarHeight()) - AndroidUtilities.dp(60.0f));
            if (ChatAttachAlert.this.gridExtraSpace != newSize2) {
                ChatAttachAlert.this.gridExtraSpace = newSize2;
                ChatAttachAlert.this.adapter.notifyDataSetChanged();
            }
            if (!AndroidUtilities.isTablet() && AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y) {
                padding = availableHeight / 6;
            } else {
                int padding2 = availableHeight / 5;
                padding = padding2 * 2;
            }
            if (ChatAttachAlert.this.gridView.getPaddingTop() != padding) {
                ChatAttachAlert.this.gridView.setPadding(AndroidUtilities.dp(6.0f), padding, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(48.0f));
            }
            this.ignoreLayout = false;
            onMeasureInternal(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(totalHeight, 1073741824));
        }

        public /* synthetic */ void lambda$onMeasure$0$ChatAttachAlert$2() {
            ChatAttachAlert.this.buttonsAdapter.notifyDataSetChanged();
        }

        public /* synthetic */ void lambda$onMeasure$1$ChatAttachAlert$2() {
            ChatAttachAlert.this.adapter.notifyDataSetChanged();
        }

        private void onMeasureInternal(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
            setMeasuredDimension(widthSize, heightSize);
            int widthSize2 = widthSize - (ChatAttachAlert.this.backgroundPaddingLeft * 2);
            int keyboardSize = getKeyboardHeight();
            if (keyboardSize <= AndroidUtilities.dp(20.0f)) {
                if (!AndroidUtilities.isInMultiwindow) {
                    heightSize -= ChatAttachAlert.this.commentTextView.getEmojiPadding();
                    heightMeasureSpec = View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824);
                }
            } else {
                this.ignoreLayout = true;
                ChatAttachAlert.this.commentTextView.hideEmojiView();
                this.ignoreLayout = false;
            }
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                if (child != null && child.getVisibility() != 8) {
                    if (ChatAttachAlert.this.commentTextView != null && ChatAttachAlert.this.commentTextView.isPopupView(child)) {
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
                if (ChatAttachAlert.this.adapter != null) {
                    ChatAttachAlert.this.adapter.notifyDataSetChanged();
                }
                if (ChatAttachAlert.this.sendPopupWindow != null && ChatAttachAlert.this.sendPopupWindow.isShowing()) {
                    ChatAttachAlert.this.sendPopupWindow.dismiss();
                }
            }
            int count = getChildCount();
            int paddingBottom = (getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow || AndroidUtilities.isTablet()) ? 0 : ChatAttachAlert.this.commentTextView.getEmojiPadding();
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
                        childLeft = (((childLeft3 - width) - lp.rightMargin) - getPaddingRight()) - ChatAttachAlert.this.backgroundPaddingLeft;
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
                    if (ChatAttachAlert.this.commentTextView != null && ChatAttachAlert.this.commentTextView.isPopupView(child)) {
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
            ChatAttachAlert.this.updateLayout(false);
            ChatAttachAlert.this.checkCameraViewPosition();
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
            int offset = AndroidUtilities.dp(13.0f) + (ChatAttachAlert.this.selectedMenuItem != null ? AndroidUtilities.dp(ChatAttachAlert.this.selectedMenuItem.getAlpha() * 26.0f) : 0);
            int top = (ChatAttachAlert.this.scrollOffsetY - ChatAttachAlert.this.backgroundPaddingTop) - offset;
            if (ChatAttachAlert.this.currentSheetAnimationType == 1) {
                top = (int) (top + ChatAttachAlert.this.gridView.getTranslationY());
            }
            int y = AndroidUtilities.dp(20.0f) + top;
            int height = getMeasuredHeight() + AndroidUtilities.dp(15.0f) + ChatAttachAlert.this.backgroundPaddingTop;
            float rad = 1.0f;
            if (ChatAttachAlert.this.backgroundPaddingTop + top < ActionBar.getCurrentActionBarHeight()) {
                float toMove = AndroidUtilities.dp(4.0f) + offset;
                float moveProgress = Math.min(1.0f, ((ActionBar.getCurrentActionBarHeight() - top) - ChatAttachAlert.this.backgroundPaddingTop) / toMove);
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
            ChatAttachAlert.this.shadowDrawable.setBounds(0, top, getMeasuredWidth(), height);
            ChatAttachAlert.this.shadowDrawable.draw(canvas);
            if (rad != 1.0f) {
                Theme.dialogs_onlineCirclePaint.setColor(Theme.getColor(Theme.key_dialogBackground));
                this.rect.set(ChatAttachAlert.this.backgroundPaddingLeft, ChatAttachAlert.this.backgroundPaddingTop + top, getMeasuredWidth() - ChatAttachAlert.this.backgroundPaddingLeft, ChatAttachAlert.this.backgroundPaddingTop + top + AndroidUtilities.dp(24.0f));
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(12.0f) * rad, AndroidUtilities.dp(12.0f) * rad, Theme.dialogs_onlineCirclePaint);
            }
            if ((ChatAttachAlert.this.selectedMenuItem == null || ChatAttachAlert.this.selectedMenuItem.getAlpha() != 1.0f) && rad != 0.0f) {
                float alphaProgress = ChatAttachAlert.this.selectedMenuItem != null ? 1.0f - ChatAttachAlert.this.selectedMenuItem.getAlpha() : 1.0f;
                int w = AndroidUtilities.dp(36.0f);
                this.rect.set((getMeasuredWidth() - w) / 2, y, (getMeasuredWidth() + w) / 2, AndroidUtilities.dp(4.0f) + y);
                int color = Theme.getColor(Theme.key_sheet_scrollUp);
                int alpha = Color.alpha(color);
                Theme.dialogs_onlineCirclePaint.setColor(color);
                Theme.dialogs_onlineCirclePaint.setAlpha((int) (alpha * alphaProgress * rad));
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), Theme.dialogs_onlineCirclePaint);
            }
            int color1 = Theme.getColor(Theme.key_dialogBackground);
            int finalColor = Color.argb((int) (ChatAttachAlert.this.actionBar.getAlpha() * 255.0f), (int) (Color.red(color1) * 0.8f), (int) (Color.green(color1) * 0.8f), (int) (Color.blue(color1) * 0.8f));
            Theme.dialogs_onlineCirclePaint.setColor(finalColor);
            canvas.drawRect(ChatAttachAlert.this.backgroundPaddingLeft, 0.0f, getMeasuredWidth() - ChatAttachAlert.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight, Theme.dialogs_onlineCirclePaint);
        }

        @Override // android.view.View
        public void setTranslationY(float translationY) {
            if (ChatAttachAlert.this.currentSheetAnimationType == 0) {
                this.initialTranslationY = translationY;
            }
            if (ChatAttachAlert.this.currentSheetAnimationType == 1) {
                if (translationY < 0.0f) {
                    ChatAttachAlert.this.gridView.setTranslationY(translationY);
                    float scale = (translationY / 40.0f) * (-0.1f);
                    int N = ChatAttachAlert.this.gridView.getChildCount();
                    for (int a = 0; a < N; a++) {
                        View child = ChatAttachAlert.this.gridView.getChildAt(a);
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
                    ChatAttachAlert.this.buttonsRecyclerView.setTranslationY(0.0f);
                } else {
                    ChatAttachAlert.this.gridView.setTranslationY(0.0f);
                    ChatAttachAlert.this.buttonsRecyclerView.setTranslationY((-translationY) + (ChatAttachAlert.this.buttonsRecyclerView.getMeasuredHeight() * (translationY / this.initialTranslationY)));
                }
            }
            super.setTranslationY(translationY);
            ChatAttachAlert.this.checkCameraViewPosition();
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.ChatAttachAlert$4, reason: invalid class name */
    class AnonymousClass4 extends ActionBar.ActionBarMenuOnItemClick {
        final /* synthetic */ BaseFragment val$parentFragment;

        AnonymousClass4(BaseFragment baseFragment) {
            this.val$parentFragment = baseFragment;
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id == -1) {
                ChatAttachAlert.this.dismiss();
                return;
            }
            if ((id == 0 || id == 1) && ChatAttachAlert.this.maxSelectedPhotos > 0 && ChatAttachAlert.selectedPhotosOrder.size() > 1 && (ChatAttachAlert.this.baseFragment instanceof ChatActivity)) {
                ChatActivity chatActivity = (ChatActivity) ChatAttachAlert.this.baseFragment;
                TLRPC.Chat chat = chatActivity.getCurrentChat();
                if (chat != null && !ChatObject.hasAdminRights(chat) && chat.slowmode_enabled) {
                    AlertsCreator.createSimpleAlert(ChatAttachAlert.this.getContext(), LocaleController.getString("Slowmode", R.string.Slowmode), LocaleController.getString("SlowmodeSendError", R.string.SlowmodeSendError)).show();
                    return;
                }
            }
            if (id == 0) {
                if (ChatAttachAlert.this.editingMessageObject == null) {
                    BaseFragment baseFragment = this.val$parentFragment;
                    if ((baseFragment instanceof ChatActivity) && ((ChatActivity) baseFragment).isInScheduleMode()) {
                        AlertsCreator.createScheduleDatePickerDialog(ChatAttachAlert.this.getContext(), UserObject.isUserSelf(((ChatActivity) this.val$parentFragment).getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$4$C6sUUhjC1TvhNuBlE-pVulrrk6g
                            @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                            public final void didSelectDate(boolean z, int i) {
                                this.f$0.lambda$onItemClick$0$ChatAttachAlert$4(z, i);
                            }
                        });
                        return;
                    }
                }
                ChatAttachAlert.this.applyCaption();
                ChatAttachAlert.this.delegate.didPressedButton(7, false, true, 0);
                return;
            }
            if (id == 1) {
                if (ChatAttachAlert.this.editingMessageObject == null) {
                    BaseFragment baseFragment2 = this.val$parentFragment;
                    if ((baseFragment2 instanceof ChatActivity) && ((ChatActivity) baseFragment2).isInScheduleMode()) {
                        AlertsCreator.createScheduleDatePickerDialog(ChatAttachAlert.this.getContext(), UserObject.isUserSelf(((ChatActivity) this.val$parentFragment).getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$4$eeBZc5BQAGoggfc2LSx_2x1GDDI
                            @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                            public final void didSelectDate(boolean z, int i) {
                                this.f$0.lambda$onItemClick$1$ChatAttachAlert$4(z, i);
                            }
                        });
                        return;
                    }
                }
                ChatAttachAlert.this.applyCaption();
                ChatAttachAlert.this.delegate.didPressedButton(4, true, true, 0);
                return;
            }
            if (id >= 10) {
                ChatAttachAlert chatAttachAlert = ChatAttachAlert.this;
                chatAttachAlert.selectedAlbumEntry = (MediaController.AlbumEntry) chatAttachAlert.dropDownAlbums.get(id - 10);
                if (ChatAttachAlert.this.selectedAlbumEntry == ChatAttachAlert.this.galleryAlbumEntry) {
                    ChatAttachAlert.this.dropDown.setText(LocaleController.getString("ChatGallery", R.string.ChatGallery));
                } else {
                    ChatAttachAlert.this.dropDown.setText(ChatAttachAlert.this.selectedAlbumEntry.bucketName);
                }
                ChatAttachAlert.this.adapter.notifyDataSetChanged();
                ChatAttachAlert.this.cameraAttachAdapter.notifyDataSetChanged();
                ChatAttachAlert.this.layoutManager.scrollToPositionWithOffset(0, (-ChatAttachAlert.this.gridView.getPaddingTop()) + AndroidUtilities.dp(7.0f));
            }
        }

        public /* synthetic */ void lambda$onItemClick$0$ChatAttachAlert$4(boolean notify, int scheduleDate) {
            ChatAttachAlert.this.applyCaption();
            ChatAttachAlert.this.delegate.didPressedButton(7, false, notify, scheduleDate);
        }

        public /* synthetic */ void lambda$onItemClick$1$ChatAttachAlert$4(boolean notify, int scheduleDate) {
            ChatAttachAlert.this.applyCaption();
            ChatAttachAlert.this.delegate.didPressedButton(4, true, notify, scheduleDate);
        }
    }

    public /* synthetic */ void lambda$new$0$ChatAttachAlert(int id) {
        this.actionBar.getActionBarMenuOnItemClick().onItemClick(id);
    }

    public /* synthetic */ void lambda$new$1$ChatAttachAlert(View v) {
        this.selectedMenuItem.toggleSubMenu();
    }

    public /* synthetic */ void lambda$new$2$ChatAttachAlert(View view, int position) {
        BaseFragment baseFragment;
        ChatActivity chatActivity;
        int type;
        if (!this.mediaEnabled || (baseFragment = this.baseFragment) == null || baseFragment.getParentActivity() == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 23) {
            if (position == 0 && this.noCameraPermissions) {
                try {
                    this.baseFragment.getParentActivity().requestPermissions(new String[]{"android.permission.CAMERA"}, 18);
                    return;
                } catch (Exception e) {
                    return;
                }
            } else if (this.noGalleryPermissions) {
                try {
                    this.baseFragment.getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 4);
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
            PhotoViewer.getInstance().setParentActivity(this.baseFragment.getParentActivity());
            PhotoViewer.getInstance().setParentAlert(this);
            PhotoViewer.getInstance().setMaxSelectedPhotos(this.maxSelectedPhotos, this.allowOrder);
            BaseFragment baseFragment2 = this.baseFragment;
            if (baseFragment2 instanceof ChatActivity) {
                ChatActivity chatActivity2 = (ChatActivity) baseFragment2;
                chatActivity = chatActivity2;
                type = 0;
            } else {
                chatActivity = null;
                type = 4;
            }
            PhotoViewer.getInstance().openPhotoForSelect(arrayList, position, type, this.photoViewerProvider, chatActivity);
            AndroidUtilities.hideKeyboard(this.baseFragment.getFragmentView().findFocus());
            return;
        }
        if (SharedConfig.inappCamera) {
            openCamera(true);
            return;
        }
        ChatAttachViewDelegate chatAttachViewDelegate = this.delegate;
        if (chatAttachViewDelegate != null) {
            chatAttachViewDelegate.didPressedButton(0, false, true, 0);
        }
    }

    public /* synthetic */ boolean lambda$new$3$ChatAttachAlert(View view, int position) {
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

    public /* synthetic */ void lambda$new$4$ChatAttachAlert(View view) {
        this.dropDownContainer.toggleSubMenu();
    }

    public /* synthetic */ void lambda$new$5$ChatAttachAlert(View view, int position) {
        if (view instanceof AttachButton) {
            AttachButton attachButton = (AttachButton) view;
            this.delegate.didPressedButton(((Integer) attachButton.getTag()).intValue(), true, true, 0);
        } else if (view instanceof AttachBotButton) {
            AttachBotButton button = (AttachBotButton) view;
            this.delegate.didSelectBot(button.currentUser);
            dismiss();
        }
    }

    public /* synthetic */ boolean lambda$new$7$ChatAttachAlert(View view, int position) {
        if (!(view instanceof AttachBotButton)) {
            return false;
        }
        final AttachBotButton button = (AttachBotButton) view;
        if (this.baseFragment == null || button.currentUser == null) {
            return false;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.formatString("ChatHintsDelete", R.string.ChatHintsDelete, ContactsController.formatName(button.currentUser.first_name, button.currentUser.last_name)));
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$lDQ7NKL7ghdwjxANQrIMDCueQro
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$6$ChatAttachAlert(button, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
        return true;
    }

    public /* synthetic */ void lambda$null$6$ChatAttachAlert(AttachBotButton button, DialogInterface dialogInterface, int i) {
        MediaDataController.getInstance(this.currentAccount).removeInline(button.currentUser.id);
    }

    static /* synthetic */ boolean lambda$new$8(View v, MotionEvent event) {
        return true;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.ChatAttachAlert$12, reason: invalid class name */
    class AnonymousClass12 extends EditTextEmoji {
        AnonymousClass12(Context context, SizeNotifierFrameLayout parent, BaseFragment fragment, int style) {
            super(context, parent, fragment, style);
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            if (!ChatAttachAlert.this.enterCommentEventSent) {
                ChatAttachAlert.this.delegate.needEnterComment();
                ChatAttachAlert.this.setFocusable(true);
                ChatAttachAlert.this.enterCommentEventSent = true;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$12$xFWK-BIRRcWhl7RK_Q1ORT_VxNs
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onInterceptTouchEvent$0$ChatAttachAlert$12();
                    }
                });
            }
            return super.onInterceptTouchEvent(ev);
        }

        public /* synthetic */ void lambda$onInterceptTouchEvent$0$ChatAttachAlert$12() {
            ChatAttachAlert.this.commentTextView.openKeyboard();
        }
    }

    public /* synthetic */ void lambda$new$9$ChatAttachAlert(BaseFragment parentFragment, View v) {
        if (this.editingMessageObject == null && (parentFragment instanceof ChatActivity) && ((ChatActivity) parentFragment).isInScheduleMode()) {
            AlertsCreator.createScheduleDatePickerDialog(getContext(), UserObject.isUserSelf(((ChatActivity) parentFragment).getCurrentUser()), new $$Lambda$ChatAttachAlert$iDoehNH4BjDBRyNNjmV2rp4A6g(this));
        } else {
            sendPressed(true, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x00a3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ boolean lambda$new$12$ChatAttachAlert(android.view.View r24) {
        /*
            Method dump skipped, instruction units count: 454
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.ChatAttachAlert.lambda$new$12$ChatAttachAlert(android.view.View):boolean");
    }

    public /* synthetic */ void lambda$null$10$ChatAttachAlert(KeyEvent keyEvent) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (keyEvent.getKeyCode() == 4 && keyEvent.getRepeatCount() == 0 && (actionBarPopupWindow = this.sendPopupWindow) != null && actionBarPopupWindow.isShowing()) {
            this.sendPopupWindow.dismiss();
        }
    }

    public /* synthetic */ void lambda$null$11$ChatAttachAlert(int num, TLRPC.User user, View v) {
        ActionBarPopupWindow actionBarPopupWindow = this.sendPopupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.sendPopupWindow.dismiss();
        }
        if (num == 0) {
            AlertsCreator.createScheduleDatePickerDialog(getContext(), UserObject.isUserSelf(user), new $$Lambda$ChatAttachAlert$iDoehNH4BjDBRyNNjmV2rp4A6g(this));
        } else if (num == 1) {
            sendPressed(true, 0);
        }
    }

    public /* synthetic */ void lambda$new$13$ChatAttachAlert(View v) {
        if (this.cameraView == null) {
            return;
        }
        openPhotoViewer(null, false, false);
        CameraController.getInstance().stopPreview(this.cameraView.getCameraSession());
    }

    public /* synthetic */ void lambda$new$14$ChatAttachAlert(float zoom) {
        CameraView cameraView = this.cameraView;
        if (cameraView != null) {
            this.cameraZoom = zoom;
            cameraView.setZoom(zoom);
        }
        showZoomControls(true, true);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.ChatAttachAlert$17, reason: invalid class name */
    class AnonymousClass17 implements ShutterButton.ShutterButtonDelegate {
        private File outputFile;
        final /* synthetic */ BaseFragment val$parentFragment;
        private boolean zoomingWas;

        AnonymousClass17(BaseFragment baseFragment) {
            this.val$parentFragment = baseFragment;
        }

        @Override // im.uwrkaxlmjj.ui.components.ShutterButton.ShutterButtonDelegate
        public boolean shutterLongPressed() {
            if (!(ChatAttachAlert.this.baseFragment instanceof ChatActivity) || ChatAttachAlert.this.mediaCaptured || ChatAttachAlert.this.takingPhoto || ChatAttachAlert.this.baseFragment == null || ChatAttachAlert.this.baseFragment.getParentActivity() == null || ChatAttachAlert.this.cameraView == null) {
                return false;
            }
            if (Build.VERSION.SDK_INT >= 23 && ChatAttachAlert.this.baseFragment.getParentActivity().checkSelfPermission("android.permission.RECORD_AUDIO") != 0) {
                ChatAttachAlert.this.requestingPermissions = true;
                ChatAttachAlert.this.baseFragment.getParentActivity().requestPermissions(new String[]{"android.permission.RECORD_AUDIO"}, 21);
                return false;
            }
            for (int a = 0; a < 2; a++) {
                ChatAttachAlert.this.flashModeButton[a].setAlpha(0.0f);
            }
            ChatAttachAlert.this.switchCameraButton.setAlpha(0.0f);
            ChatAttachAlert.this.tooltipTextView.setAlpha(0.0f);
            this.outputFile = AndroidUtilities.generateVideoPath((ChatAttachAlert.this.baseFragment instanceof ChatActivity) && ((ChatActivity) ChatAttachAlert.this.baseFragment).isSecretChat());
            ChatAttachAlert.this.recordTime.setAlpha(1.0f);
            ChatAttachAlert.this.recordTime.setText(String.format("%02d:%02d", 0, 0));
            ChatAttachAlert.this.videoRecordTime = 0;
            ChatAttachAlert.this.videoRecordRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$17$OS9HEehgpN3Kfh-753cJOrcibHg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$shutterLongPressed$0$ChatAttachAlert$17();
                }
            };
            AndroidUtilities.lockOrientation(this.val$parentFragment.getParentActivity());
            CameraController.getInstance().recordVideo(ChatAttachAlert.this.cameraView.getCameraSession(), this.outputFile, new CameraController.VideoTakeCallback() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$17$LZWMeG9Hu34vSv4A1BJ1SBTkZf0
                @Override // im.uwrkaxlmjj.messenger.camera.CameraController.VideoTakeCallback
                public final void onFinishVideoRecording(String str, long j) {
                    this.f$0.lambda$shutterLongPressed$1$ChatAttachAlert$17(str, j);
                }
            }, new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$17$hwNQCn2RKo8rUqN_gCqGytv0Uoc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$shutterLongPressed$2$ChatAttachAlert$17();
                }
            });
            ChatAttachAlert.this.shutterButton.setState(ShutterButton.State.RECORDING, true);
            return true;
        }

        public /* synthetic */ void lambda$shutterLongPressed$0$ChatAttachAlert$17() {
            if (ChatAttachAlert.this.videoRecordRunnable == null) {
                return;
            }
            ChatAttachAlert.access$8508(ChatAttachAlert.this);
            ChatAttachAlert.this.recordTime.setText(String.format("%02d:%02d", Integer.valueOf(ChatAttachAlert.this.videoRecordTime / 60), Integer.valueOf(ChatAttachAlert.this.videoRecordTime % 60)));
            AndroidUtilities.runOnUIThread(ChatAttachAlert.this.videoRecordRunnable, 1000L);
        }

        public /* synthetic */ void lambda$shutterLongPressed$1$ChatAttachAlert$17(String thumbPath, long duration) {
            if (this.outputFile != null && ChatAttachAlert.this.baseFragment != null) {
                boolean unused = ChatAttachAlert.mediaFromExternalCamera = false;
                MediaController.PhotoEntry photoEntry = new MediaController.PhotoEntry(0, ChatAttachAlert.access$9310(), 0L, this.outputFile.getAbsolutePath(), 0, true);
                photoEntry.duration = (int) duration;
                photoEntry.thumbPath = thumbPath;
                ChatAttachAlert.this.openPhotoViewer(photoEntry, false, false);
            }
        }

        public /* synthetic */ void lambda$shutterLongPressed$2$ChatAttachAlert$17() {
            AndroidUtilities.runOnUIThread(ChatAttachAlert.this.videoRecordRunnable, 1000L);
        }

        @Override // im.uwrkaxlmjj.ui.components.ShutterButton.ShutterButtonDelegate
        public void shutterCancel() {
            if (ChatAttachAlert.this.mediaCaptured) {
                return;
            }
            File file = this.outputFile;
            if (file != null) {
                file.delete();
                this.outputFile = null;
            }
            ChatAttachAlert.this.resetRecordState();
            CameraController.getInstance().stopVideoRecording(ChatAttachAlert.this.cameraView.getCameraSession(), true);
        }

        @Override // im.uwrkaxlmjj.ui.components.ShutterButton.ShutterButtonDelegate
        public void shutterReleased() {
            if (!ChatAttachAlert.this.takingPhoto && ChatAttachAlert.this.cameraView != null && !ChatAttachAlert.this.mediaCaptured && ChatAttachAlert.this.cameraView.getCameraSession() != null) {
                ChatAttachAlert.this.mediaCaptured = true;
                if (ChatAttachAlert.this.shutterButton.getState() == ShutterButton.State.RECORDING) {
                    ChatAttachAlert.this.resetRecordState();
                    CameraController.getInstance().stopVideoRecording(ChatAttachAlert.this.cameraView.getCameraSession(), false);
                    ChatAttachAlert.this.shutterButton.setState(ShutterButton.State.DEFAULT, true);
                } else {
                    final File cameraFile = AndroidUtilities.generatePicturePath((ChatAttachAlert.this.baseFragment instanceof ChatActivity) && ((ChatActivity) ChatAttachAlert.this.baseFragment).isSecretChat());
                    final boolean sameTakePictureOrientation = ChatAttachAlert.this.cameraView.getCameraSession().isSameTakePictureOrientation();
                    ChatAttachAlert.this.cameraView.getCameraSession().setFlipFront(this.val$parentFragment instanceof ChatActivity);
                    ChatAttachAlert.this.takingPhoto = CameraController.getInstance().takePicture(cameraFile, ChatAttachAlert.this.cameraView.getCameraSession(), new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$17$3TbUx6RxFof7Wbot6FOjar0tskE
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$shutterReleased$3$ChatAttachAlert$17(cameraFile, sameTakePictureOrientation);
                        }
                    });
                }
            }
        }

        public /* synthetic */ void lambda$shutterReleased$3$ChatAttachAlert$17(File cameraFile, boolean sameTakePictureOrientation) {
            ChatAttachAlert.this.takingPhoto = false;
            if (cameraFile == null || ChatAttachAlert.this.baseFragment == null) {
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
            boolean unused = ChatAttachAlert.mediaFromExternalCamera = false;
            MediaController.PhotoEntry photoEntry = new MediaController.PhotoEntry(0, ChatAttachAlert.access$9310(), 0L, cameraFile.getAbsolutePath(), orientation, false);
            photoEntry.canDeleteAfter = true;
            ChatAttachAlert.this.openPhotoViewer(photoEntry, sameTakePictureOrientation, false);
        }

        @Override // im.uwrkaxlmjj.ui.components.ShutterButton.ShutterButtonDelegate
        public boolean onTranslationChanged(float x, float y) {
            boolean isPortrait = ChatAttachAlert.this.container.getWidth() < ChatAttachAlert.this.container.getHeight();
            float val1 = isPortrait ? x : y;
            float val2 = isPortrait ? y : x;
            if (!this.zoomingWas && Math.abs(val1) > Math.abs(val2)) {
                return ChatAttachAlert.this.zoomControlView.getTag() == null;
            }
            if (val2 < 0.0f) {
                ChatAttachAlert.this.showZoomControls(true, true);
                ChatAttachAlert.this.zoomControlView.setZoom((-val2) / AndroidUtilities.dp(200.0f), true);
                this.zoomingWas = true;
                return false;
            }
            if (this.zoomingWas) {
                ChatAttachAlert.this.zoomControlView.setZoom(0.0f, true);
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

    public /* synthetic */ void lambda$new$15$ChatAttachAlert(View v) {
        CameraView cameraView;
        if (this.takingPhoto || (cameraView = this.cameraView) == null || !cameraView.isInitied()) {
            return;
        }
        this.cameraInitied = false;
        this.cameraView.switchCamera();
        ObjectAnimator animator = ObjectAnimator.ofFloat(this.switchCameraButton, (Property<ImageView, Float>) View.SCALE_X, 0.0f).setDuration(100L);
        animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.18
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator2) {
                ChatAttachAlert.this.switchCameraButton.setImageResource((ChatAttachAlert.this.cameraView == null || !ChatAttachAlert.this.cameraView.isFrontface()) ? R.drawable.camera_revert2 : R.drawable.camera_revert1);
                ObjectAnimator.ofFloat(ChatAttachAlert.this.switchCameraButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f).setDuration(100L).start();
            }
        });
        animator.start();
    }

    public /* synthetic */ void lambda$new$16$ChatAttachAlert(final View currentImage) {
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
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.19
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                ChatAttachAlert.this.flashAnimationInProgress = false;
                currentImage.setVisibility(4);
                nextImage.sendAccessibilityEvent(8);
            }
        });
        animatorSet.start();
    }

    static /* synthetic */ void lambda$new$17(View view, int position) {
        if (view instanceof PhotoAttachPhotoCell) {
            ((PhotoAttachPhotoCell) view).callDelegate();
        }
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
        this.buttonsAdapter.notifyDataSetChanged();
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

    /* JADX INFO: Access modifiers changed from: private */
    public void sendPressed(boolean notify, int scheduleDate) {
        if (this.buttonPressed) {
            return;
        }
        BaseFragment baseFragment = this.baseFragment;
        if (baseFragment instanceof ChatActivity) {
            ChatActivity chatActivity = (ChatActivity) baseFragment;
            TLRPC.Chat chat = chatActivity.getCurrentChat();
            TLRPC.User user = chatActivity.getCurrentUser();
            if (user != null || ((ChatObject.isChannel(chat) && chat.megagroup) || !ChatObject.isChannel(chat))) {
                MessagesController.getNotificationsSettings(this.currentAccount).edit().putBoolean("silent_" + chatActivity.getDialogId(), !notify).commit();
            }
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

    private boolean showCommentTextView(final boolean show, boolean animated) {
        if (show == (this.frameLayout2.getTag() != null)) {
            return false;
        }
        AnimatorSet animatorSet = this.animatorSet;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.frameLayout2.setTag(show ? 1 : null);
        if (this.commentTextView.getEditText().isFocused()) {
            AndroidUtilities.hideKeyboard(this.commentTextView.getEditText());
        }
        this.commentTextView.hidePopup(true);
        if (show) {
            this.frameLayout2.setVisibility(0);
            this.writeButtonContainer.setVisibility(0);
        }
        if (animated) {
            this.animatorSet = new AnimatorSet();
            ArrayList<Animator> animators = new ArrayList<>();
            FrameLayout frameLayout = this.frameLayout2;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            animators.add(ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property, fArr));
            FrameLayout frameLayout2 = this.writeButtonContainer;
            Property property2 = View.SCALE_X;
            float[] fArr2 = new float[1];
            fArr2[0] = show ? 1.0f : 0.2f;
            animators.add(ObjectAnimator.ofFloat(frameLayout2, (Property<FrameLayout, Float>) property2, fArr2));
            FrameLayout frameLayout3 = this.writeButtonContainer;
            Property property3 = View.SCALE_Y;
            float[] fArr3 = new float[1];
            fArr3[0] = show ? 1.0f : 0.2f;
            animators.add(ObjectAnimator.ofFloat(frameLayout3, (Property<FrameLayout, Float>) property3, fArr3));
            FrameLayout frameLayout4 = this.writeButtonContainer;
            Property property4 = View.ALPHA;
            float[] fArr4 = new float[1];
            fArr4[0] = show ? 1.0f : 0.0f;
            animators.add(ObjectAnimator.ofFloat(frameLayout4, (Property<FrameLayout, Float>) property4, fArr4));
            View view = this.selectedCountView;
            Property property5 = View.SCALE_X;
            float[] fArr5 = new float[1];
            fArr5[0] = show ? 1.0f : 0.2f;
            animators.add(ObjectAnimator.ofFloat(view, (Property<View, Float>) property5, fArr5));
            View view2 = this.selectedCountView;
            Property property6 = View.SCALE_Y;
            float[] fArr6 = new float[1];
            fArr6[0] = show ? 1.0f : 0.2f;
            animators.add(ObjectAnimator.ofFloat(view2, (Property<View, Float>) property6, fArr6));
            View view3 = this.selectedCountView;
            Property property7 = View.ALPHA;
            float[] fArr7 = new float[1];
            fArr7[0] = show ? 1.0f : 0.0f;
            animators.add(ObjectAnimator.ofFloat(view3, (Property<View, Float>) property7, fArr7));
            if (this.actionBar.getTag() != null) {
                FrameLayout frameLayout5 = this.frameLayout2;
                Property property8 = View.TRANSLATION_Y;
                float[] fArr8 = new float[1];
                fArr8[0] = show ? 0.0f : AndroidUtilities.dp(48.0f);
                animators.add(ObjectAnimator.ofFloat(frameLayout5, (Property<FrameLayout, Float>) property8, fArr8));
                View view4 = this.shadow;
                Property property9 = View.TRANSLATION_Y;
                float[] fArr9 = new float[1];
                fArr9[0] = show ? AndroidUtilities.dp(44.0f) : AndroidUtilities.dp(92.0f);
                animators.add(ObjectAnimator.ofFloat(view4, (Property<View, Float>) property9, fArr9));
                View view5 = this.shadow;
                Property property10 = View.ALPHA;
                float[] fArr10 = new float[1];
                fArr10[0] = show ? 1.0f : 0.0f;
                animators.add(ObjectAnimator.ofFloat(view5, (Property<View, Float>) property10, fArr10));
            } else {
                RecyclerListView recyclerListView = this.buttonsRecyclerView;
                Property property11 = View.TRANSLATION_Y;
                float[] fArr11 = new float[1];
                fArr11[0] = show ? AndroidUtilities.dp(44.0f) : 0.0f;
                animators.add(ObjectAnimator.ofFloat(recyclerListView, (Property<RecyclerListView, Float>) property11, fArr11));
                View view6 = this.shadow;
                Property property12 = View.TRANSLATION_Y;
                float[] fArr12 = new float[1];
                fArr12[0] = show ? AndroidUtilities.dp(44.0f) : 0.0f;
                animators.add(ObjectAnimator.ofFloat(view6, (Property<View, Float>) property12, fArr12));
            }
            this.animatorSet.playTogether(animators);
            this.animatorSet.setInterpolator(new DecelerateInterpolator());
            this.animatorSet.setDuration(180L);
            this.animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.22
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(ChatAttachAlert.this.animatorSet)) {
                        if (!show) {
                            ChatAttachAlert.this.frameLayout2.setVisibility(4);
                            ChatAttachAlert.this.writeButtonContainer.setVisibility(4);
                        }
                        ChatAttachAlert.this.animatorSet = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (animation.equals(ChatAttachAlert.this.animatorSet)) {
                        ChatAttachAlert.this.animatorSet = null;
                    }
                }
            });
            this.animatorSet.start();
        } else {
            this.frameLayout2.setAlpha(show ? 1.0f : 0.0f);
            this.writeButtonContainer.setScaleX(show ? 1.0f : 0.2f);
            this.writeButtonContainer.setScaleY(show ? 1.0f : 0.2f);
            this.writeButtonContainer.setAlpha(show ? 1.0f : 0.0f);
            this.selectedCountView.setScaleX(show ? 1.0f : 0.2f);
            this.selectedCountView.setScaleY(show ? 1.0f : 0.2f);
            this.selectedCountView.setAlpha(show ? 1.0f : 0.0f);
            if (this.actionBar.getTag() != null) {
                this.frameLayout2.setTranslationY(show ? 0.0f : AndroidUtilities.dp(48.0f));
                this.shadow.setTranslationY(show ? AndroidUtilities.dp(44.0f) : AndroidUtilities.dp(92.0f));
                this.shadow.setAlpha(show ? 1.0f : 0.0f);
            } else {
                this.buttonsRecyclerView.setTranslationY(show ? AndroidUtilities.dp(44.0f) : 0.0f);
                this.shadow.setTranslationY(show ? AndroidUtilities.dp(44.0f) : 0.0f);
            }
            if (!show) {
                this.frameLayout2.setVisibility(4);
                this.writeButtonContainer.setVisibility(4);
            }
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean onCustomOpenAnimation() {
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(this, this.ATTACH_ALERT_PROGRESS, 0.0f, 400.0f));
        animatorSet.setDuration(400L);
        animatorSet.setStartDelay(20L);
        animatorSet.start();
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openPhotoViewer(MediaController.PhotoEntry entry, boolean sameTakePictureOrientation, boolean external) {
        ChatActivity chatActivity;
        int type;
        if (entry != null) {
            cameraPhotos.add(entry);
            selectedPhotos.put(Integer.valueOf(entry.imageId), entry);
            selectedPhotosOrder.add(Integer.valueOf(entry.imageId));
            updatePhotosButton(0);
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
        PhotoViewer.getInstance().setParentActivity(this.baseFragment.getParentActivity());
        PhotoViewer.getInstance().setParentAlert(this);
        PhotoViewer.getInstance().setMaxSelectedPhotos(this.maxSelectedPhotos, this.allowOrder);
        BaseFragment baseFragment = this.baseFragment;
        if (baseFragment instanceof ChatActivity) {
            chatActivity = (ChatActivity) baseFragment;
            type = 2;
        } else {
            chatActivity = null;
            type = 5;
        }
        PhotoViewer.getInstance().openPhotoForSelect(getAllPhotosArray(), cameraPhotos.size() - 1, type, new AnonymousClass24(sameTakePictureOrientation), chatActivity);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.ChatAttachAlert$24, reason: invalid class name */
    class AnonymousClass24 extends BasePhotoProvider {
        final /* synthetic */ boolean val$sameTakePictureOrientation;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        AnonymousClass24(boolean z) {
            super();
            this.val$sameTakePictureOrientation = z;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public ImageReceiver.BitmapHolder getThumbForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean cancelButtonPressed() {
            if (ChatAttachAlert.this.cameraOpened && ChatAttachAlert.this.cameraView != null) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$24$qLJgLzZL3MefZK4afGNIMvSxUTo
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$cancelButtonPressed$0$ChatAttachAlert$24();
                    }
                }, 1000L);
                ChatAttachAlert.this.zoomControlView.setZoom(0.0f, false);
                ChatAttachAlert.this.cameraZoom = 0.0f;
                ChatAttachAlert.this.cameraView.setZoom(0.0f);
                CameraController.getInstance().startPreview(ChatAttachAlert.this.cameraView.getCameraSession());
            }
            if (ChatAttachAlert.this.cancelTakingPhotos && ChatAttachAlert.cameraPhotos.size() == 1) {
                int size = ChatAttachAlert.cameraPhotos.size();
                for (int a = 0; a < size; a++) {
                    MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) ChatAttachAlert.cameraPhotos.get(a);
                    new File(photoEntry.path).delete();
                    if (photoEntry.imagePath != null) {
                        new File(photoEntry.imagePath).delete();
                    }
                    if (photoEntry.thumbPath != null) {
                        new File(photoEntry.thumbPath).delete();
                    }
                }
                ChatAttachAlert.cameraPhotos.clear();
                ChatAttachAlert.selectedPhotosOrder.clear();
                ChatAttachAlert.selectedPhotos.clear();
                ChatAttachAlert.this.counterTextView.setVisibility(4);
                ChatAttachAlert.this.cameraPhotoRecyclerView.setVisibility(8);
                ChatAttachAlert.this.adapter.notifyDataSetChanged();
                ChatAttachAlert.this.cameraAttachAdapter.notifyDataSetChanged();
                ChatAttachAlert.this.updatePhotosButton(0);
            }
            return true;
        }

        public /* synthetic */ void lambda$cancelButtonPressed$0$ChatAttachAlert$24() {
            if (ChatAttachAlert.this.cameraView != null && !ChatAttachAlert.this.isDismissed() && Build.VERSION.SDK_INT >= 21) {
                ChatAttachAlert.this.cameraView.setSystemUiVisibility(1028);
            }
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void needAddMorePhotos() {
            ChatAttachAlert.this.cancelTakingPhotos = false;
            if (ChatAttachAlert.mediaFromExternalCamera) {
                ChatAttachAlert.this.delegate.didPressedButton(0, true, true, 0);
                return;
            }
            if (!ChatAttachAlert.this.cameraOpened) {
                ChatAttachAlert.this.openCamera(false);
            }
            ChatAttachAlert.this.counterTextView.setVisibility(0);
            ChatAttachAlert.this.cameraPhotoRecyclerView.setVisibility(0);
            ChatAttachAlert.this.counterTextView.setAlpha(1.0f);
            ChatAttachAlert.this.updatePhotosCounter(false);
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
            if (ChatAttachAlert.cameraPhotos.isEmpty() || ChatAttachAlert.this.baseFragment == null) {
                return;
            }
            if (videoEditedInfo != null && index >= 0 && index < ChatAttachAlert.cameraPhotos.size()) {
                MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) ChatAttachAlert.cameraPhotos.get(index);
                photoEntry.editedInfo = videoEditedInfo;
            }
            if (!(ChatAttachAlert.this.baseFragment instanceof ChatActivity) || !((ChatActivity) ChatAttachAlert.this.baseFragment).isSecretChat()) {
                int size = ChatAttachAlert.cameraPhotos.size();
                for (int a = 0; a < size; a++) {
                    AndroidUtilities.addMediaToGallery(((MediaController.PhotoEntry) ChatAttachAlert.cameraPhotos.get(a)).path);
                }
            }
            ChatAttachAlert.this.applyCaption();
            ChatAttachAlert.this.delegate.didPressedButton(8, true, notify, scheduleDate);
            ChatAttachAlert.cameraPhotos.clear();
            ChatAttachAlert.selectedPhotosOrder.clear();
            ChatAttachAlert.selectedPhotos.clear();
            ChatAttachAlert.this.adapter.notifyDataSetChanged();
            ChatAttachAlert.this.cameraAttachAdapter.notifyDataSetChanged();
            ChatAttachAlert.this.closeCamera(false);
            ChatAttachAlert.this.dismiss();
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean scaleToFill() {
            if (ChatAttachAlert.this.baseFragment == null || ChatAttachAlert.this.baseFragment.getParentActivity() == null) {
                return false;
            }
            int locked = Settings.System.getInt(ChatAttachAlert.this.baseFragment.getParentActivity().getContentResolver(), "accelerometer_rotation", 0);
            return this.val$sameTakePictureOrientation || locked == 1;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void willHidePhotoViewer() {
            ChatAttachAlert.this.mediaCaptured = false;
            int count = ChatAttachAlert.this.gridView.getChildCount();
            for (int a = 0; a < count; a++) {
                View view = ChatAttachAlert.this.gridView.getChildAt(a);
                if (view instanceof PhotoAttachPhotoCell) {
                    PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                    cell.showImage();
                    cell.showCheck(true);
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean canScrollAway() {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean canCaptureMorePhotos() {
            return ChatAttachAlert.this.maxSelectedPhotos != 1;
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
                Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$Yz0SmxadoVWQUlZHYmb-h4s_jD8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$showZoomControls$18$ChatAttachAlert();
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
        this.zoomControlAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.25
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                ChatAttachAlert.this.zoomControlAnimation = null;
            }
        });
        this.zoomControlAnimation.start();
        if (show) {
            Runnable runnable3 = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$MIdBY0Y3sxnDxfjDX4mhf55otXM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$showZoomControls$19$ChatAttachAlert();
                }
            };
            this.zoomControlHideRunnable = runnable3;
            AndroidUtilities.runOnUIThread(runnable3, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }
    }

    public /* synthetic */ void lambda$showZoomControls$18$ChatAttachAlert() {
        showZoomControls(false, true);
        this.zoomControlHideRunnable = null;
    }

    public /* synthetic */ void lambda$showZoomControls$19$ChatAttachAlert() {
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

    /* JADX INFO: Access modifiers changed from: private */
    public void applyAttachButtonColors(View view) {
        if (view instanceof AttachButton) {
            AttachButton button = (AttachButton) view;
            button.textView.setTextColor(Theme.getColor(Theme.key_dialogTextGray2));
        } else if (view instanceof AttachBotButton) {
            AttachBotButton button2 = (AttachBotButton) view;
            button2.nameTextView.setTextColor(Theme.getColor(Theme.key_dialogTextGray2));
        }
    }

    public void checkColors() {
        RecyclerListView recyclerListView = this.buttonsRecyclerView;
        if (recyclerListView == null) {
            return;
        }
        int count = recyclerListView.getChildCount();
        for (int a = 0; a < count; a++) {
            applyAttachButtonColors(this.buttonsRecyclerView.getChildAt(a));
        }
        this.selectedTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.selectedMenuItem.setIconColor(Theme.getColor(Theme.key_dialogTextBlack));
        Theme.setDrawableColor(this.selectedMenuItem.getBackground(), Theme.getColor(Theme.key_dialogButtonSelector));
        this.selectedMenuItem.setPopupItemsColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem), false);
        this.selectedMenuItem.setPopupItemsColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem), true);
        this.selectedMenuItem.redrawPopup(Theme.getColor(Theme.key_actionBarDefaultSubmenuBackground));
        this.commentTextView.updateColors();
        ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = this.sendPopupLayout;
        if (actionBarPopupWindowLayout != null) {
            actionBarPopupWindowLayout.getBackgroundDrawable().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarDefaultSubmenuBackground), PorterDuff.Mode.MULTIPLY));
            int a2 = 0;
            while (true) {
                ActionBarMenuSubItem[] actionBarMenuSubItemArr = this.itemCells;
                if (a2 >= actionBarMenuSubItemArr.length) {
                    break;
                }
                actionBarMenuSubItemArr[a2].setColors(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem), Theme.getColor(Theme.key_actionBarDefaultSubmenuItem));
                a2++;
            }
        }
        Theme.setSelectorDrawableColor(this.writeButtonDrawable, Theme.getColor(Theme.key_dialogFloatingButton), false);
        Theme.setSelectorDrawableColor(this.writeButtonDrawable, Theme.getColor(Theme.key_dialogFloatingButtonPressed), true);
        this.writeButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogFloatingIcon), PorterDuff.Mode.MULTIPLY));
        this.dropDown.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.dropDownContainer.setPopupItemsColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem), false);
        this.dropDownContainer.setPopupItemsColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem), true);
        this.dropDownContainer.redrawPopup(Theme.getColor(Theme.key_actionBarDefaultSubmenuBackground));
        this.actionBarShadow.setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        this.progressView.setTextColor(Theme.getColor(Theme.key_emptyListPlaceholder));
        this.buttonsRecyclerView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        this.buttonsRecyclerView.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.frameLayout2.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.selectedCountView.invalidate();
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
        if (this.baseFragment == null) {
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
        AndroidUtilities.unlockOrientation(this.baseFragment.getParentActivity());
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
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.ChatAttachAlert.setCameraFlashModeIcon(android.widget.ImageView, java.lang.String):void");
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
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.26
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    ChatAttachAlert.this.cameraAnimationInProgress = false;
                    if (Build.VERSION.SDK_INT >= 21 && ChatAttachAlert.this.cameraView != null) {
                        ChatAttachAlert.this.cameraView.invalidateOutline();
                    }
                    if (ChatAttachAlert.this.cameraOpened) {
                        ChatAttachAlert.this.delegate.onCameraOpened();
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

    /* JADX WARN: Removed duplicated region for block: B:62:0x011e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onActivityResultFragment(int r23, android.content.Intent r24, java.lang.String r25) {
        /*
            Method dump skipped, instruction units count: 464
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.ChatAttachAlert.onActivityResultFragment(int, android.content.Intent, java.lang.String):void");
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
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.27
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    ChatAttachAlert.this.cameraAnimationInProgress = false;
                    if (Build.VERSION.SDK_INT >= 21 && ChatAttachAlert.this.cameraView != null) {
                        ChatAttachAlert.this.cameraView.invalidateOutline();
                    }
                    ChatAttachAlert.this.cameraOpened = false;
                    if (ChatAttachAlert.this.cameraPanel != null) {
                        ChatAttachAlert.this.cameraPanel.setVisibility(8);
                    }
                    if (ChatAttachAlert.this.zoomControlView != null) {
                        ChatAttachAlert.this.zoomControlView.setVisibility(8);
                        ChatAttachAlert.this.zoomControlView.setTag(null);
                    }
                    if (ChatAttachAlert.this.cameraPhotoRecyclerView != null) {
                        ChatAttachAlert.this.cameraPhotoRecyclerView.setVisibility(8);
                    }
                    if (Build.VERSION.SDK_INT >= 21 && ChatAttachAlert.this.cameraView != null) {
                        ChatAttachAlert.this.cameraView.setSystemUiVisibility(1024);
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
                int maxY2 = (int) ((containerHeight - this.buttonsRecyclerView.getMeasuredHeight()) + this.buttonsRecyclerView.getTranslationY() + this.containerView.getTranslationY());
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
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$C3MuXExB5R-b8dbFLhNf5yGiz80
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$applyCameraViewPosition$20$ChatAttachAlert(layoutParams);
                        }
                    });
                }
            }
            final FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.cameraIcon.getLayoutParams();
            if (layoutParams2.height != finalHeight || layoutParams2.width != finalWidth) {
                layoutParams2.width = finalWidth;
                layoutParams2.height = finalHeight;
                this.cameraIcon.setLayoutParams(layoutParams2);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$1CgWbVWt0JCXOU47LKx3dftW8lU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$applyCameraViewPosition$21$ChatAttachAlert(layoutParams2);
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$applyCameraViewPosition$20$ChatAttachAlert(FrameLayout.LayoutParams layoutParamsFinal) {
        CameraView cameraView = this.cameraView;
        if (cameraView != null) {
            cameraView.setLayoutParams(layoutParamsFinal);
        }
    }

    public /* synthetic */ void lambda$applyCameraViewPosition$21$ChatAttachAlert(FrameLayout.LayoutParams layoutParamsFinal) {
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
            CameraView cameraView = new CameraView(this.baseFragment.getParentActivity(), this.openWithFrontFaceCamera);
            this.cameraView = cameraView;
            cameraView.setFocusable(true);
            if (Build.VERSION.SDK_INT >= 21) {
                this.cameraView.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.28
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view, Outline outline) {
                        if (ChatAttachAlert.this.cameraAnimationInProgress) {
                            int rad = AndroidUtilities.dp(ChatAttachAlert.this.cornerRadius * 8.0f * ChatAttachAlert.this.cameraOpenProgress);
                            outline.setRoundRect(0, 0, view.getMeasuredWidth() + rad, view.getMeasuredHeight() + rad, rad);
                        } else if (!ChatAttachAlert.this.cameraAnimationInProgress && !ChatAttachAlert.this.cameraOpened) {
                            int rad2 = AndroidUtilities.dp(ChatAttachAlert.this.cornerRadius * 8.0f);
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
            this.cameraView.setDelegate(new CameraView.CameraViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.29
                @Override // im.uwrkaxlmjj.messenger.camera.CameraView.CameraViewDelegate
                public void onCameraCreated(Camera camera) {
                }

                @Override // im.uwrkaxlmjj.messenger.camera.CameraView.CameraViewDelegate
                public void onCameraInit() {
                    String current = ChatAttachAlert.this.cameraView.getCameraSession().getCurrentFlashMode();
                    String next = ChatAttachAlert.this.cameraView.getCameraSession().getNextFlashMode();
                    if (current.equals(next)) {
                        for (int a = 0; a < 2; a++) {
                            ChatAttachAlert.this.flashModeButton[a].setVisibility(4);
                            ChatAttachAlert.this.flashModeButton[a].setAlpha(0.0f);
                            ChatAttachAlert.this.flashModeButton[a].setTranslationY(0.0f);
                        }
                    } else {
                        ChatAttachAlert chatAttachAlert = ChatAttachAlert.this;
                        chatAttachAlert.setCameraFlashModeIcon(chatAttachAlert.flashModeButton[0], ChatAttachAlert.this.cameraView.getCameraSession().getCurrentFlashMode());
                        int a2 = 0;
                        while (a2 < 2) {
                            ChatAttachAlert.this.flashModeButton[a2].setVisibility(a2 == 0 ? 0 : 4);
                            ChatAttachAlert.this.flashModeButton[a2].setAlpha((a2 == 0 && ChatAttachAlert.this.cameraOpened) ? 1.0f : 0.0f);
                            ChatAttachAlert.this.flashModeButton[a2].setTranslationY(0.0f);
                            a2++;
                        }
                    }
                    ChatAttachAlert.this.switchCameraButton.setImageResource(ChatAttachAlert.this.cameraView.isFrontface() ? R.drawable.camera_revert1 : R.drawable.camera_revert2);
                    ChatAttachAlert.this.switchCameraButton.setVisibility(ChatAttachAlert.this.cameraView.hasFrontFaceCamera() ? 0 : 4);
                    if (!ChatAttachAlert.this.cameraOpened) {
                        ChatAttachAlert.this.cameraInitAnimation = new AnimatorSet();
                        ChatAttachAlert.this.cameraInitAnimation.playTogether(ObjectAnimator.ofFloat(ChatAttachAlert.this.cameraView, (Property<CameraView, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(ChatAttachAlert.this.cameraIcon, (Property<FrameLayout, Float>) View.ALPHA, 0.0f, 1.0f));
                        ChatAttachAlert.this.cameraInitAnimation.setDuration(180L);
                        ChatAttachAlert.this.cameraInitAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.29.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (animation.equals(ChatAttachAlert.this.cameraInitAnimation)) {
                                    ChatAttachAlert.this.cameraInitAnimation = null;
                                    int count = ChatAttachAlert.this.gridView.getChildCount();
                                    for (int a3 = 0; a3 < count; a3++) {
                                        View child = ChatAttachAlert.this.gridView.getChildAt(a3);
                                        if (child instanceof PhotoAttachCameraCell) {
                                            child.setVisibility(4);
                                            return;
                                        }
                                    }
                                }
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationCancel(Animator animation) {
                                ChatAttachAlert.this.cameraInitAnimation = null;
                            }
                        });
                        ChatAttachAlert.this.cameraInitAnimation.start();
                    }
                }
            });
            if (this.cameraIcon == null) {
                FrameLayout frameLayout = new FrameLayout(this.baseFragment.getParentActivity()) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.30
                    @Override // android.view.View
                    protected void onDraw(Canvas canvas) {
                        int w = ChatAttachAlert.this.cameraDrawable.getIntrinsicWidth();
                        int h = ChatAttachAlert.this.cameraDrawable.getIntrinsicHeight();
                        int x = (ChatAttachAlert.this.itemSize - w) / 2;
                        int y = (ChatAttachAlert.this.itemSize - h) / 2;
                        if (ChatAttachAlert.this.cameraViewOffsetY != 0) {
                            y -= ChatAttachAlert.this.cameraViewOffsetY;
                        }
                        ChatAttachAlert.this.cameraDrawable.setBounds(x, y, x + w, y + h);
                        ChatAttachAlert.this.cameraDrawable.draw(canvas);
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
        try {
            TextureView textureView = this.cameraView.getTextureView();
            Bitmap bitmap = textureView.getBitmap();
            if (bitmap != null) {
                Bitmap newBitmap = Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(), bitmap.getHeight(), this.cameraView.getMatrix(), true);
                bitmap.recycle();
                Bitmap lastBitmap = Bitmap.createScaledBitmap(newBitmap, 80, (int) (newBitmap.getHeight() / (newBitmap.getWidth() / 80.0f)), true);
                if (lastBitmap != null) {
                    if (lastBitmap != newBitmap) {
                        newBitmap.recycle();
                    }
                    Utilities.blurBitmap(lastBitmap, 7, 1, lastBitmap.getWidth(), lastBitmap.getHeight(), lastBitmap.getRowBytes());
                    File file = new File(ApplicationLoader.getFilesDirFixed(), "cthumb.jpg");
                    FileOutputStream stream = new FileOutputStream(file);
                    lastBitmap.compress(Bitmap.CompressFormat.JPEG, 87, stream);
                    lastBitmap.recycle();
                }
            }
        } catch (Throwable th) {
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.albumsDidLoad) {
            if (this.adapter != null) {
                if (this.baseFragment instanceof ChatActivity) {
                    this.galleryAlbumEntry = MediaController.allMediaAlbumEntry;
                } else {
                    this.galleryAlbumEntry = MediaController.allPhotosAlbumEntry;
                }
                if (this.selectedAlbumEntry == null) {
                    this.selectedAlbumEntry = this.galleryAlbumEntry;
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
        if (id == NotificationCenter.reloadInlineHints) {
            ButtonsAdapter buttonsAdapter = this.buttonsAdapter;
            if (buttonsAdapter != null) {
                buttonsAdapter.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.cameraInitied) {
            checkCamera(false);
        }
    }

    private void updateAlbumsDropDown() {
        final ArrayList<MediaController.AlbumEntry> albums;
        this.dropDownContainer.removeAllSubItems();
        if (this.mediaEnabled) {
            if (this.baseFragment instanceof ChatActivity) {
                albums = MediaController.allMediaAlbums;
            } else {
                albums = MediaController.allPhotoAlbums;
            }
            ArrayList<MediaController.AlbumEntry> arrayList = new ArrayList<>(albums);
            this.dropDownAlbums = arrayList;
            Collections.sort(arrayList, new Comparator() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$xfr2y5nmY27uxZr3BUNNQVX99Ck
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return ChatAttachAlert.lambda$updateAlbumsDropDown$22(albums, (MediaController.AlbumEntry) obj, (MediaController.AlbumEntry) obj2);
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

    static /* synthetic */ int lambda$updateAlbumsDropDown$22(ArrayList albums, MediaController.AlbumEntry o1, MediaController.AlbumEntry o2) {
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

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSelectedPosition() {
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
        float offset = this.actionBar.getAlpha() == 0.0f ? AndroidUtilities.dp((1.0f - this.selectedMenuItem.getAlpha()) * 26.0f) : 0.0f;
        this.selectedMenuItem.setTranslationY((this.scrollOffsetY - AndroidUtilities.dp((finalMove * moveProgress) + 37.0f)) + offset);
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
            this.actionBarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.31
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    ChatAttachAlert.this.actionBarAnimation = null;
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

    public void updatePhotosButton(int animated) {
        int count = selectedPhotos.size();
        if (count == 0) {
            this.selectedCountView.setPivotX(0.0f);
            this.selectedCountView.setPivotY(0.0f);
            showCommentTextView(false, animated != 0);
        } else {
            this.selectedCountView.invalidate();
            if (!showCommentTextView(true, animated != 0) && animated != 0) {
                this.selectedCountView.setPivotX(AndroidUtilities.dp(21.0f));
                this.selectedCountView.setPivotY(AndroidUtilities.dp(12.0f));
                AnimatorSet animatorSet = new AnimatorSet();
                Animator[] animatorArr = new Animator[2];
                View view = this.selectedCountView;
                Property property = View.SCALE_X;
                float[] fArr = new float[2];
                fArr[0] = animated == 1 ? 1.1f : 0.9f;
                fArr[1] = 1.0f;
                animatorArr[0] = ObjectAnimator.ofFloat(view, (Property<View, Float>) property, fArr);
                View view2 = this.selectedCountView;
                Property property2 = View.SCALE_Y;
                float[] fArr2 = new float[2];
                fArr2[0] = animated != 1 ? 0.9f : 1.1f;
                fArr2[1] = 1.0f;
                animatorArr[1] = ObjectAnimator.ofFloat(view2, (Property<View, Float>) property2, fArr2);
                animatorSet.playTogether(animatorArr);
                animatorSet.setInterpolator(new OvershootInterpolator());
                animatorSet.setDuration(180L);
                animatorSet.start();
            } else {
                this.selectedCountView.setPivotX(0.0f);
                this.selectedCountView.setPivotY(0.0f);
            }
            if (count == 1 || this.editingMessageObject != null) {
                this.selectedMenuItem.hideSubItem(0);
            } else {
                this.selectedMenuItem.showSubItem(0);
            }
        }
        if (this.baseFragment instanceof ChatActivity) {
            if ((count == 0 && this.menuShowed) || (count != 0 && !this.menuShowed)) {
                this.menuShowed = count != 0;
                AnimatorSet animatorSet2 = this.menuAnimator;
                if (animatorSet2 != null) {
                    animatorSet2.cancel();
                    this.menuAnimator = null;
                }
                if (this.menuShowed) {
                    this.selectedMenuItem.setVisibility(0);
                    this.selectedTextView.setVisibility(0);
                }
                if (animated == 0) {
                    this.selectedMenuItem.setAlpha(this.menuShowed ? 1.0f : 0.0f);
                    this.selectedTextView.setAlpha(this.menuShowed ? 1.0f : 0.0f);
                    return;
                }
                AnimatorSet animatorSet3 = new AnimatorSet();
                this.menuAnimator = animatorSet3;
                Animator[] animatorArr2 = new Animator[2];
                ActionBarMenuItem actionBarMenuItem = this.selectedMenuItem;
                Property property3 = View.ALPHA;
                float[] fArr3 = new float[1];
                fArr3[0] = this.menuShowed ? 1.0f : 0.0f;
                animatorArr2[0] = ObjectAnimator.ofFloat(actionBarMenuItem, (Property<ActionBarMenuItem, Float>) property3, fArr3);
                TextView textView = this.selectedTextView;
                Property property4 = View.ALPHA;
                float[] fArr4 = new float[1];
                fArr4[0] = this.menuShowed ? 1.0f : 0.0f;
                animatorArr2[1] = ObjectAnimator.ofFloat(textView, (Property<TextView, Float>) property4, fArr4);
                animatorSet3.playTogether(animatorArr2);
                this.menuAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.32
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        ChatAttachAlert.this.menuAnimator = null;
                        if (!ChatAttachAlert.this.menuShowed) {
                            ChatAttachAlert.this.selectedMenuItem.setVisibility(4);
                            ChatAttachAlert.this.selectedTextView.setVisibility(4);
                        }
                    }
                });
                this.menuAnimator.setDuration(180L);
                this.menuAnimator.start();
            }
        }
    }

    public void setDelegate(ChatAttachViewDelegate chatAttachViewDelegate) {
        this.delegate = chatAttachViewDelegate;
    }

    public void loadGalleryPhotos() {
        MediaController.AlbumEntry albumEntry;
        if (this.baseFragment instanceof ChatActivity) {
            albumEntry = MediaController.allMediaAlbumEntry;
        } else {
            albumEntry = MediaController.allPhotosAlbumEntry;
        }
        if (albumEntry == null && Build.VERSION.SDK_INT >= 21) {
            MediaController.loadGalleryPhotosAlbums(0);
        }
    }

    public void init() {
        if (this.baseFragment instanceof ChatActivity) {
            this.galleryAlbumEntry = MediaController.allMediaAlbumEntry;
            TLRPC.Chat chat = ((ChatActivity) this.baseFragment).getCurrentChat();
            if (chat != null) {
                this.mediaEnabled = ChatObject.canSendMedia(chat);
                this.pollsEnabled = ChatObject.canSendPolls(chat);
                if (this.mediaEnabled) {
                    this.progressView.setText(LocaleController.getString("NoPhotos", R.string.NoPhotos));
                } else if (ChatObject.isActionBannedByDefault(chat, 7)) {
                    this.progressView.setText(LocaleController.getString("GlobalAttachMediaRestricted", R.string.GlobalAttachMediaRestricted));
                } else if (AndroidUtilities.isBannedForever(chat.banned_rights)) {
                    this.progressView.setText(LocaleController.formatString("AttachMediaRestrictedForever", R.string.AttachMediaRestrictedForever, new Object[0]));
                } else {
                    this.progressView.setText(LocaleController.formatString("AttachMediaRestricted", R.string.AttachMediaRestricted, LocaleController.formatDateForBan(chat.banned_rights.until_date)));
                }
                CameraView cameraView = this.cameraView;
                if (cameraView != null) {
                    cameraView.setAlpha(this.mediaEnabled ? 1.0f : 0.2f);
                    this.cameraView.setEnabled(this.mediaEnabled);
                }
                FrameLayout frameLayout = this.cameraIcon;
                if (frameLayout != null) {
                    frameLayout.setAlpha(this.mediaEnabled ? 1.0f : 0.2f);
                    this.cameraIcon.setEnabled(this.mediaEnabled);
                }
            } else {
                this.pollsEnabled = false;
            }
        } else {
            this.galleryAlbumEntry = MediaController.allPhotosAlbumEntry;
            this.commentTextView.setVisibility(4);
        }
        if (Build.VERSION.SDK_INT >= 23) {
            this.noGalleryPermissions = this.baseFragment.getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0;
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
        this.dropDown.setText(LocaleController.getString("ChatGallery", R.string.ChatGallery));
        clearSelectedPhotos();
        updatePhotosCounter(false);
        this.buttonsAdapter.notifyDataSetChanged();
        this.commentTextView.setText("");
        this.cameraPhotoLayoutManager.scrollToPositionWithOffset(0, EditInputFilter.MAX_VALUE);
        this.buttonsLayoutManager.scrollToPositionWithOffset(0, EditInputFilter.MAX_VALUE);
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
        this.baseFragment = null;
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
            boolean z = this.baseFragment.getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0;
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
        if (this.baseFragment == null) {
            return;
        }
        boolean old = this.deviceHasGoodCamera;
        boolean old2 = this.noCameraPermissions;
        if (!SharedConfig.inappCamera) {
            this.deviceHasGoodCamera = false;
        } else if (Build.VERSION.SDK_INT >= 23) {
            boolean z = this.baseFragment.getParentActivity().checkSelfPermission("android.permission.CAMERA") != 0;
            this.noCameraPermissions = z;
            if (z) {
                if (request) {
                    try {
                        this.baseFragment.getParentActivity().requestPermissions(new String[]{"android.permission.CAMERA"}, 17);
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
        } else {
            if (request || SharedConfig.hasCameraCache) {
                CameraController.getInstance().initCamera(null);
            }
            this.deviceHasGoodCamera = CameraController.getInstance().isCameraInitied();
        }
        if ((old != this.deviceHasGoodCamera || old2 != this.noCameraPermissions) && (photoAttachAdapter = this.adapter) != null) {
            photoAttachAdapter.notifyDataSetChanged();
        }
        if (isShowing() && this.deviceHasGoodCamera && this.baseFragment != null && this.backDrawable.getAlpha() != 0 && !this.cameraOpened) {
            showCamera();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegateInterface
    public void onOpenAnimationEnd() {
        MediaController.AlbumEntry albumEntry;
        NotificationCenter.getInstance(this.currentAccount).setAnimationInProgress(false);
        if (this.baseFragment instanceof ChatActivity) {
            albumEntry = MediaController.allMediaAlbumEntry;
        } else {
            albumEntry = MediaController.allPhotosAlbumEntry;
        }
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
        updatePhotosButton(0);
        this.adapter.notifyDataSetChanged();
        this.cameraAttachAdapter.notifyDataSetChanged();
    }

    private class ButtonsAdapter extends RecyclerListView.SelectionAdapter {
        private int buttonsCount;
        private int contactButton;
        private int documentButton;
        private int galleryButton;
        private int locationButton;
        private Context mContext;
        private int musicButton;
        private int pollButton;

        public ButtonsAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = ChatAttachAlert.this.new AttachButton(this.mContext);
            } else {
                view = ChatAttachAlert.this.new AttachBotButton(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    int position2 = position - this.buttonsCount;
                    AttachBotButton child = (AttachBotButton) holder.itemView;
                    child.setTag(Integer.valueOf(position2));
                    child.setUser(MessagesController.getInstance(ChatAttachAlert.this.currentAccount).getUser(Integer.valueOf(MediaDataController.getInstance(ChatAttachAlert.this.currentAccount).inlineBots.get(position2).peer.user_id)));
                    return;
                }
                return;
            }
            AttachButton attachButton = (AttachButton) holder.itemView;
            if (position == this.galleryButton) {
                attachButton.setTextAndIcon(LocaleController.getString("ChatGallery", R.string.ChatGallery), Theme.chat_attachButtonDrawables[0]);
                attachButton.setTag(1);
                return;
            }
            if (position == this.documentButton) {
                attachButton.setTextAndIcon(LocaleController.getString("ChatDocument", R.string.ChatDocument), Theme.chat_attachButtonDrawables[2]);
                attachButton.setTag(4);
                return;
            }
            if (position == this.locationButton) {
                attachButton.setTextAndIcon(LocaleController.getString("ChatLocation", R.string.ChatLocation), Theme.chat_attachButtonDrawables[4]);
                attachButton.setTag(6);
                return;
            }
            if (position == this.musicButton) {
                attachButton.setTextAndIcon(LocaleController.getString("AttachMusic", R.string.AttachMusic), Theme.chat_attachButtonDrawables[1]);
                attachButton.setTag(3);
            } else if (position == this.pollButton) {
                attachButton.setTextAndIcon(LocaleController.getString("Poll", R.string.Poll), Theme.chat_attachButtonDrawables[5]);
                attachButton.setTag(9);
            } else if (position == this.contactButton) {
                attachButton.setTextAndIcon(LocaleController.getString("AttachContact", R.string.AttachContact), Theme.chat_attachButtonDrawables[3]);
                attachButton.setTag(5);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            ChatAttachAlert.this.applyAttachButtonColors(holder.itemView);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = this.buttonsCount;
            if (ChatAttachAlert.this.editingMessageObject == null && (ChatAttachAlert.this.baseFragment instanceof ChatActivity)) {
                return count + MediaDataController.getInstance(ChatAttachAlert.this.currentAccount).inlineBots.size();
            }
            return count;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            this.buttonsCount = 0;
            this.galleryButton = -1;
            this.documentButton = -1;
            this.musicButton = -1;
            this.pollButton = -1;
            this.contactButton = -1;
            this.locationButton = -1;
            if (ChatAttachAlert.this.baseFragment instanceof ChatActivity) {
                if (ChatAttachAlert.this.editingMessageObject == null) {
                    if (ChatAttachAlert.this.mediaEnabled) {
                        int i = this.buttonsCount;
                        int i2 = i + 1;
                        this.buttonsCount = i2;
                        this.galleryButton = i;
                        this.buttonsCount = i2 + 1;
                        this.documentButton = i2;
                    }
                    int i3 = this.buttonsCount;
                    this.buttonsCount = i3 + 1;
                    this.locationButton = i3;
                    if (ChatAttachAlert.this.pollsEnabled) {
                        int i4 = this.buttonsCount;
                        this.buttonsCount = i4 + 1;
                        this.pollButton = i4;
                    } else {
                        int i5 = this.buttonsCount;
                        this.buttonsCount = i5 + 1;
                        this.contactButton = i5;
                    }
                    if (ChatAttachAlert.this.mediaEnabled) {
                        int i6 = this.buttonsCount;
                        this.buttonsCount = i6 + 1;
                        this.musicButton = i6;
                    }
                } else {
                    int i7 = this.buttonsCount;
                    int i8 = i7 + 1;
                    this.buttonsCount = i8;
                    this.galleryButton = i7;
                    int i9 = i8 + 1;
                    this.buttonsCount = i9;
                    this.documentButton = i8;
                    this.buttonsCount = i9 + 1;
                    this.musicButton = i9;
                }
            } else {
                int i10 = this.buttonsCount;
                int i11 = i10 + 1;
                this.buttonsCount = i11;
                this.galleryButton = i10;
                this.buttonsCount = i11 + 1;
                this.documentButton = i11;
            }
            super.notifyDataSetChanged();
        }

        public int getButtonsCount() {
            return this.buttonsCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position < this.buttonsCount) {
                return 0;
            }
            return 1;
        }
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
            if (Build.VERSION.SDK_INT >= 21 && this == ChatAttachAlert.this.adapter) {
                cell.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.PhotoAttachAdapter.1
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view, Outline outline) {
                        PhotoAttachPhotoCell photoCell = (PhotoAttachPhotoCell) view;
                        int position = ((Integer) photoCell.getTag()).intValue();
                        if (PhotoAttachAdapter.this.needCamera && ChatAttachAlert.this.selectedAlbumEntry == ChatAttachAlert.this.galleryAlbumEntry) {
                            position++;
                        }
                        if (position != 0) {
                            if (position == ChatAttachAlert.this.itemsPerRow - 1) {
                                int rad = AndroidUtilities.dp(ChatAttachAlert.this.cornerRadius * 8.0f);
                                outline.setRoundRect(-rad, 0, view.getMeasuredWidth(), view.getMeasuredHeight() + rad, rad);
                                return;
                            } else {
                                outline.setRect(0, 0, view.getMeasuredWidth(), view.getMeasuredHeight());
                                return;
                            }
                        }
                        int rad2 = AndroidUtilities.dp(ChatAttachAlert.this.cornerRadius * 8.0f);
                        outline.setRoundRect(0, 0, view.getMeasuredWidth() + rad2, view.getMeasuredHeight() + rad2, rad2);
                    }
                });
                cell.setClipToOutline(true);
            }
            cell.setDelegate(new PhotoAttachPhotoCell.PhotoAttachPhotoCellDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$PhotoAttachAdapter$AoQ4aB1Y39gyHPnC-onl09bWW9I
                @Override // im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell.PhotoAttachPhotoCellDelegate
                public final void onCheckClick(PhotoAttachPhotoCell photoAttachPhotoCell) {
                    this.f$0.lambda$createHolder$0$ChatAttachAlert$PhotoAttachAdapter(photoAttachPhotoCell);
                }
            });
            return new RecyclerListView.Holder(cell);
        }

        public /* synthetic */ void lambda$createHolder$0$ChatAttachAlert$PhotoAttachAdapter(PhotoAttachPhotoCell v) {
            if (!ChatAttachAlert.this.mediaEnabled) {
                return;
            }
            int index = ((Integer) v.getTag()).intValue();
            MediaController.PhotoEntry photoEntry = v.getPhotoEntry();
            boolean added = !ChatAttachAlert.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId));
            if (!added || ChatAttachAlert.this.maxSelectedPhotos < 0 || ChatAttachAlert.selectedPhotos.size() < ChatAttachAlert.this.maxSelectedPhotos) {
                int num = added ? ChatAttachAlert.selectedPhotosOrder.size() : -1;
                if ((ChatAttachAlert.this.baseFragment instanceof ChatActivity) && ChatAttachAlert.this.allowOrder) {
                    v.setChecked(num, added, true);
                } else {
                    v.setChecked(-1, added, true);
                }
                ChatAttachAlert.this.addToSelectedPhotos(photoEntry, index);
                int updateIndex = index;
                if (this == ChatAttachAlert.this.cameraAttachAdapter) {
                    if (ChatAttachAlert.this.adapter.needCamera && ChatAttachAlert.this.selectedAlbumEntry == ChatAttachAlert.this.galleryAlbumEntry) {
                        updateIndex++;
                    }
                    ChatAttachAlert.this.adapter.notifyItemChanged(updateIndex);
                } else {
                    ChatAttachAlert.this.cameraAttachAdapter.notifyItemChanged(updateIndex);
                }
                ChatAttachAlert.this.updatePhotosButton(added ? 1 : 2);
                return;
            }
            if (ChatAttachAlert.this.allowOrder && (ChatAttachAlert.this.baseFragment instanceof ChatActivity)) {
                ChatActivity chatActivity = (ChatActivity) ChatAttachAlert.this.baseFragment;
                TLRPC.Chat chat = chatActivity.getCurrentChat();
                if (chat != null && !ChatObject.hasAdminRights(chat) && chat.slowmode_enabled && ChatAttachAlert.this.alertOnlyOnce != 2) {
                    AlertsCreator.createSimpleAlert(ChatAttachAlert.this.getContext(), LocaleController.getString("Slowmode", R.string.Slowmode), LocaleController.getString("SlowmodeSelectSendError", R.string.SlowmodeSelectSendError)).show();
                    if (ChatAttachAlert.this.alertOnlyOnce == 1) {
                        ChatAttachAlert.this.alertOnlyOnce = 2;
                    }
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public MediaController.PhotoEntry getPhoto(int position) {
            if (this.needCamera && ChatAttachAlert.this.selectedAlbumEntry == ChatAttachAlert.this.galleryAlbumEntry) {
                position--;
            }
            return ChatAttachAlert.this.getPhotoEntryAtPosition(position);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType != 1) {
                    if (itemViewType == 3) {
                        PhotoAttachPermissionCell cell = (PhotoAttachPermissionCell) holder.itemView;
                        cell.setItemSize(ChatAttachAlert.this.itemSize);
                        cell.setType((this.needCamera && ChatAttachAlert.this.noCameraPermissions && position == 0) ? 0 : 1);
                        return;
                    }
                    return;
                }
                PhotoAttachCameraCell cameraCell = (PhotoAttachCameraCell) holder.itemView;
                if (ChatAttachAlert.this.cameraView != null && ChatAttachAlert.this.cameraView.isInitied()) {
                    cameraCell.setVisibility(4);
                } else {
                    cameraCell.setVisibility(0);
                }
                cameraCell.setItemSize(ChatAttachAlert.this.itemSize);
                return;
            }
            if (this.needCamera && ChatAttachAlert.this.selectedAlbumEntry == ChatAttachAlert.this.galleryAlbumEntry) {
                position--;
            }
            PhotoAttachPhotoCell cell2 = (PhotoAttachPhotoCell) holder.itemView;
            if (this == ChatAttachAlert.this.adapter) {
                cell2.setItemSize(ChatAttachAlert.this.itemSize);
            } else {
                cell2.setIsVertical(ChatAttachAlert.this.cameraPhotoLayoutManager.getOrientation() == 1);
            }
            MediaController.PhotoEntry photoEntry = ChatAttachAlert.this.getPhotoEntryAtPosition(position);
            cell2.setPhotoEntry(photoEntry, this.needCamera && ChatAttachAlert.this.selectedAlbumEntry == ChatAttachAlert.this.galleryAlbumEntry, position == getItemCount() - 1);
            if (!(ChatAttachAlert.this.baseFragment instanceof ChatActivity) || !ChatAttachAlert.this.allowOrder) {
                cell2.setChecked(-1, ChatAttachAlert.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId)), false);
            } else {
                cell2.setChecked(ChatAttachAlert.selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry.imageId)), ChatAttachAlert.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId)), false);
            }
            cell2.getImageView().setTag(Integer.valueOf(position));
            cell2.setTag(Integer.valueOf(position));
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
                    RecyclerListView.Holder holder3 = new RecyclerListView.Holder(new View(this.mContext) { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.PhotoAttachAdapter.3
                        @Override // android.view.View
                        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                            super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(ChatAttachAlert.this.gridExtraSpace, 1073741824));
                        }
                    });
                    return holder3;
                }
                RecyclerListView.Holder holder4 = new RecyclerListView.Holder(new PhotoAttachPermissionCell(this.mContext));
                return holder4;
            }
            PhotoAttachCameraCell cameraCell = new PhotoAttachCameraCell(this.mContext);
            if (Build.VERSION.SDK_INT >= 21) {
                cameraCell.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.components.ChatAttachAlert.PhotoAttachAdapter.2
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view, Outline outline) {
                        int rad = AndroidUtilities.dp(ChatAttachAlert.this.cornerRadius * 8.0f);
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
            if (!ChatAttachAlert.this.mediaEnabled) {
                return 1;
            }
            int count = 0;
            if (this.needCamera && ChatAttachAlert.this.selectedAlbumEntry == ChatAttachAlert.this.galleryAlbumEntry) {
                count = 0 + 1;
            }
            if (ChatAttachAlert.this.noGalleryPermissions && this == ChatAttachAlert.this.adapter) {
                count++;
            }
            int count2 = count + ChatAttachAlert.cameraPhotos.size();
            if (ChatAttachAlert.this.selectedAlbumEntry != null) {
                count2 += ChatAttachAlert.this.selectedAlbumEntry.photos.size();
            }
            if (this == ChatAttachAlert.this.adapter) {
                count2++;
            }
            this.itemsCount = count2;
            return count2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (!ChatAttachAlert.this.mediaEnabled) {
                return 2;
            }
            if (this.needCamera && position == 0 && ChatAttachAlert.this.selectedAlbumEntry == ChatAttachAlert.this.galleryAlbumEntry) {
                return ChatAttachAlert.this.noCameraPermissions ? 3 : 1;
            }
            if (this == ChatAttachAlert.this.adapter && position == this.itemsCount - 1) {
                return 2;
            }
            return ChatAttachAlert.this.noGalleryPermissions ? 3 : 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
            if (this == ChatAttachAlert.this.adapter) {
                ChatAttachAlert.this.progressView.setVisibility((!(getItemCount() == 1 && ChatAttachAlert.this.selectedAlbumEntry == null) && ChatAttachAlert.this.mediaEnabled) ? 4 : 0);
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
}
