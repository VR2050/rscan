package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Property;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuSubItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.EditTextEmoji;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoPickerActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private int alertOnlyOnce;
    private boolean allowCaption;
    private boolean allowIndices;
    private AnimatorSet animatorSet;
    private CharSequence caption;
    private ChatActivity chatActivity;
    protected EditTextEmoji commentTextView;
    private PhotoPickerActivityDelegate delegate;
    private EmptyTextProgressView emptyView;
    protected FrameLayout frameLayout2;
    private int imageReqId;
    private String initialSearchString;
    boolean isFcCrop;
    private ActionBarMenuSubItem[] itemCells;
    private RecyclerViewItemRangeSelector itemRangeSelector;
    private ImageView iv;
    private String lastSearchImageString;
    private String lastSearchString;
    private int lastSearchToken;
    private GridLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private boolean loadingRecent;
    private FCPhotoPickerActivityDelegate mFCPhotoPickerActivityDelegate;
    private int maxSelectedPhotos;
    private String nextImagesSearchOffset;
    private ArrayList<MediaController.SearchImage> recentImages;
    private ActionBarMenuItem searchItem;
    private boolean searching;
    private boolean searchingUser;
    private int selectPhotoType;
    private MediaController.AlbumEntry selectedAlbum;
    protected View selectedCountView;
    private HashMap<Object, Object> selectedPhotos;
    private ArrayList<Object> selectedPhotosOrder;
    private ActionBarPopupWindow.ActionBarPopupWindowLayout sendPopupLayout;
    private ActionBarPopupWindow sendPopupWindow;
    private boolean sendPressed;
    protected View shadow;
    private boolean shouldSelect;
    private SizeNotifierFrameLayout sizeNotifierFrameLayout;
    private int type;
    private ImageView writeButton;
    protected FrameLayout writeButtonContainer;
    private Drawable writeButtonDrawable;
    private ArrayList<MediaController.SearchImage> searchResult = new ArrayList<>();
    private HashMap<String, MediaController.SearchImage> searchResultKeys = new HashMap<>();
    private HashMap<String, MediaController.SearchImage> searchResultUrls = new HashMap<>();
    private boolean imageSearchEndReached = true;
    private boolean allowOrder = true;
    private int itemSize = 100;
    private int itemsPerRow = 3;
    private TextPaint textPaint = new TextPaint(1);
    private RectF rect = new RectF();
    private Paint paint = new Paint(1);
    private boolean needsBottomLayout = true;
    private boolean mblnSendOriginal = false;
    private PhotoViewer.PhotoViewerProvider provider = new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.1
        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean scaleToFill() {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
            PhotoAttachPhotoCell cell = PhotoPickerActivity.this.getCellForIndex(index);
            if (cell != null) {
                BackupImageView imageView = cell.getImageView();
                int[] coords = new int[2];
                imageView.getLocationInWindow(coords);
                PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
                object.viewX = coords[0];
                object.viewY = coords[1] - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight);
                object.parentView = PhotoPickerActivity.this.listView;
                object.imageReceiver = imageView.getImageReceiver();
                object.thumb = object.imageReceiver.getBitmapSafe();
                object.scale = cell.getScale();
                cell.showCheck(false);
                return object;
            }
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void updatePhotoAtIndex(int index) {
            PhotoAttachPhotoCell cell = PhotoPickerActivity.this.getCellForIndex(index);
            if (cell != null) {
                if (PhotoPickerActivity.this.selectedAlbum == null) {
                    ArrayList<MediaController.SearchImage> array = (PhotoPickerActivity.this.searchResult.isEmpty() && PhotoPickerActivity.this.lastSearchString == null) ? PhotoPickerActivity.this.recentImages : PhotoPickerActivity.this.searchResult;
                    cell.setPhotoEntry(array.get(index), true, false);
                    return;
                }
                BackupImageView imageView = cell.getImageView();
                imageView.setOrientation(0, true);
                MediaController.PhotoEntry photoEntry = PhotoPickerActivity.this.selectedAlbum.photos.get(index);
                if (photoEntry.thumbPath != null) {
                    imageView.setImage(photoEntry.thumbPath, null, Theme.chat_attachEmptyDrawable);
                    return;
                }
                if (photoEntry.path != null) {
                    imageView.setOrientation(photoEntry.orientation, true);
                    if (photoEntry.isVideo) {
                        imageView.setImage("vthumb://" + photoEntry.imageId + LogUtils.COLON + photoEntry.path, null, Theme.chat_attachEmptyDrawable);
                        return;
                    }
                    imageView.setImage("thumb://" + photoEntry.imageId + LogUtils.COLON + photoEntry.path, null, Theme.chat_attachEmptyDrawable);
                    return;
                }
                imageView.setImageDrawable(Theme.chat_attachEmptyDrawable);
            }
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean allowCaption() {
            return PhotoPickerActivity.this.allowCaption;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public ImageReceiver.BitmapHolder getThumbForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
            PhotoAttachPhotoCell cell = PhotoPickerActivity.this.getCellForIndex(index);
            if (cell != null) {
                return cell.getImageView().getImageReceiver().getBitmapSafe();
            }
            return null;
        }

        /* JADX WARN: Removed duplicated region for block: B:23:0x006e  */
        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void willSwitchFromPhoto(im.uwrkaxlmjj.messenger.MessageObject r8, im.uwrkaxlmjj.tgnet.TLRPC.FileLocation r9, int r10) {
            /*
                r7 = this;
                im.uwrkaxlmjj.ui.PhotoPickerActivity r0 = im.uwrkaxlmjj.ui.PhotoPickerActivity.this
                im.uwrkaxlmjj.ui.components.RecyclerListView r0 = im.uwrkaxlmjj.ui.PhotoPickerActivity.access$100(r0)
                int r0 = r0.getChildCount()
                r1 = 0
            Lb:
                if (r1 >= r0) goto L78
                im.uwrkaxlmjj.ui.PhotoPickerActivity r2 = im.uwrkaxlmjj.ui.PhotoPickerActivity.this
                im.uwrkaxlmjj.ui.components.RecyclerListView r2 = im.uwrkaxlmjj.ui.PhotoPickerActivity.access$100(r2)
                android.view.View r2 = r2.getChildAt(r1)
                java.lang.Object r3 = r2.getTag()
                if (r3 != 0) goto L1e
                goto L75
            L1e:
                r3 = r2
                im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell r3 = (im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell) r3
                java.lang.Object r4 = r2.getTag()
                java.lang.Integer r4 = (java.lang.Integer) r4
                int r4 = r4.intValue()
                im.uwrkaxlmjj.ui.PhotoPickerActivity r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.this
                im.uwrkaxlmjj.messenger.MediaController$AlbumEntry r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.access$200(r5)
                if (r5 == 0) goto L44
                if (r4 < 0) goto L75
                im.uwrkaxlmjj.ui.PhotoPickerActivity r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.this
                im.uwrkaxlmjj.messenger.MediaController$AlbumEntry r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.access$200(r5)
                java.util.ArrayList<im.uwrkaxlmjj.messenger.MediaController$PhotoEntry> r5 = r5.photos
                int r5 = r5.size()
                if (r4 < r5) goto L6e
                goto L75
            L44:
                im.uwrkaxlmjj.ui.PhotoPickerActivity r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.this
                java.util.ArrayList r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.access$300(r5)
                boolean r5 = r5.isEmpty()
                if (r5 == 0) goto L5f
                im.uwrkaxlmjj.ui.PhotoPickerActivity r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.this
                java.lang.String r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.access$400(r5)
                if (r5 != 0) goto L5f
                im.uwrkaxlmjj.ui.PhotoPickerActivity r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.this
                java.util.ArrayList r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.access$500(r5)
                goto L65
            L5f:
                im.uwrkaxlmjj.ui.PhotoPickerActivity r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.this
                java.util.ArrayList r5 = im.uwrkaxlmjj.ui.PhotoPickerActivity.access$300(r5)
            L65:
                if (r4 < 0) goto L75
                int r6 = r5.size()
                if (r4 < r6) goto L6e
                goto L75
            L6e:
                if (r4 != r10) goto L75
                r5 = 1
                r3.showCheck(r5)
                goto L78
            L75:
                int r1 = r1 + 1
                goto Lb
            L78:
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PhotoPickerActivity.AnonymousClass1.willSwitchFromPhoto(im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.tgnet.TLRPC$FileLocation, int):void");
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void willHidePhotoViewer() {
            int count = PhotoPickerActivity.this.listView.getChildCount();
            for (int a = 0; a < count; a++) {
                View view = PhotoPickerActivity.this.listView.getChildAt(a);
                if (view instanceof PhotoAttachPhotoCell) {
                    PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                    cell.showCheck(true);
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean isPhotoChecked(int index) {
            if (PhotoPickerActivity.this.selectedAlbum != null) {
                return index >= 0 && index < PhotoPickerActivity.this.selectedAlbum.photos.size() && PhotoPickerActivity.this.selectedPhotos.containsKey(Integer.valueOf(PhotoPickerActivity.this.selectedAlbum.photos.get(index).imageId));
            }
            ArrayList<MediaController.SearchImage> array = (PhotoPickerActivity.this.searchResult.isEmpty() && PhotoPickerActivity.this.lastSearchString == null) ? PhotoPickerActivity.this.recentImages : PhotoPickerActivity.this.searchResult;
            return index >= 0 && index < array.size() && PhotoPickerActivity.this.selectedPhotos.containsKey(array.get(index).id);
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int setPhotoUnchecked(Object object) {
            Object key = null;
            if (object instanceof MediaController.PhotoEntry) {
                key = Integer.valueOf(((MediaController.PhotoEntry) object).imageId);
            } else if (object instanceof MediaController.SearchImage) {
                key = ((MediaController.SearchImage) object).id;
            }
            if (key != null && PhotoPickerActivity.this.selectedPhotos.containsKey(key)) {
                PhotoPickerActivity.this.selectedPhotos.remove(key);
                int position = PhotoPickerActivity.this.selectedPhotosOrder.indexOf(key);
                if (position >= 0) {
                    PhotoPickerActivity.this.selectedPhotosOrder.remove(position);
                }
                if (PhotoPickerActivity.this.allowIndices) {
                    PhotoPickerActivity.this.updateCheckedPhotoIndices();
                }
                return position;
            }
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int setPhotoChecked(int index, VideoEditedInfo videoEditedInfo) {
            int num;
            boolean add = true;
            if (PhotoPickerActivity.this.selectedAlbum == null) {
                ArrayList<MediaController.SearchImage> array = (PhotoPickerActivity.this.searchResult.isEmpty() && PhotoPickerActivity.this.lastSearchString == null) ? PhotoPickerActivity.this.recentImages : PhotoPickerActivity.this.searchResult;
                if (index < 0 || index >= array.size()) {
                    return -1;
                }
                MediaController.SearchImage photoEntry = array.get(index);
                int num2 = PhotoPickerActivity.this.addToSelectedPhotos(photoEntry, -1);
                if (num2 == -1) {
                    num = PhotoPickerActivity.this.selectedPhotosOrder.indexOf(photoEntry.id);
                } else {
                    add = false;
                    num = num2;
                }
            } else {
                if (index < 0 || index >= PhotoPickerActivity.this.selectedAlbum.photos.size()) {
                    return -1;
                }
                MediaController.PhotoEntry photoEntry2 = PhotoPickerActivity.this.selectedAlbum.photos.get(index);
                int iAddToSelectedPhotos = PhotoPickerActivity.this.addToSelectedPhotos(photoEntry2, -1);
                num = iAddToSelectedPhotos;
                if (iAddToSelectedPhotos == -1) {
                    photoEntry2.editedInfo = videoEditedInfo;
                    num = PhotoPickerActivity.this.selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry2.imageId));
                } else {
                    add = false;
                    photoEntry2.editedInfo = null;
                }
            }
            int count = PhotoPickerActivity.this.listView.getChildCount();
            int a = 0;
            while (true) {
                if (a >= count) {
                    break;
                }
                View view = PhotoPickerActivity.this.listView.getChildAt(a);
                int tag = ((Integer) view.getTag()).intValue();
                if (tag == index) {
                    ((PhotoAttachPhotoCell) view).setChecked(PhotoPickerActivity.this.allowIndices ? num : -1, add, false);
                } else {
                    a++;
                }
            }
            PhotoPickerActivity.this.updatePhotosButton(add ? 1 : 2);
            PhotoPickerActivity.this.delegate.selectedPhotosChanged();
            return num;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean cancelButtonPressed() {
            PhotoPickerActivity.this.delegate.actionButtonPressed(true, true, 0, PhotoPickerActivity.this.mblnSendOriginal);
            PhotoPickerActivity.this.finishFragment();
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int getSelectedCount() {
            return PhotoPickerActivity.this.selectedPhotos.size();
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
            if (PhotoPickerActivity.this.selectedPhotos.isEmpty()) {
                if (PhotoPickerActivity.this.selectedAlbum == null) {
                    ArrayList<MediaController.SearchImage> array = (PhotoPickerActivity.this.searchResult.isEmpty() && PhotoPickerActivity.this.lastSearchString == null) ? PhotoPickerActivity.this.recentImages : PhotoPickerActivity.this.searchResult;
                    if (index >= 0 && index < array.size()) {
                        PhotoPickerActivity.this.addToSelectedPhotos(array.get(index), -1);
                    } else {
                        return;
                    }
                } else if (index >= 0 && index < PhotoPickerActivity.this.selectedAlbum.photos.size()) {
                    MediaController.PhotoEntry photoEntry = PhotoPickerActivity.this.selectedAlbum.photos.get(index);
                    photoEntry.editedInfo = videoEditedInfo;
                    PhotoPickerActivity.this.addToSelectedPhotos(photoEntry, -1);
                } else {
                    return;
                }
            }
            PhotoPickerActivity.this.sendSelectedPhotos(notify, scheduleDate);
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public ArrayList<Object> getSelectedPhotosOrder() {
            return PhotoPickerActivity.this.selectedPhotosOrder;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public HashMap<Object, Object> getSelectedPhotos() {
            return PhotoPickerActivity.this.selectedPhotos;
        }
    };

    public interface FCPhotoPickerActivityDelegate {
        void selectedFCPhotos(String str);
    }

    public interface PhotoPickerActivityDelegate {
        void actionButtonPressed(boolean z, boolean z2, int i, boolean z3);

        void onCaptionChanged(CharSequence charSequence);

        void selectedPhotosChanged();
    }

    public PhotoPickerActivity(int type, MediaController.AlbumEntry selectedAlbum, HashMap<Object, Object> selectedPhotos, ArrayList<Object> selectedPhotosOrder, ArrayList<MediaController.SearchImage> recentImages, int selectPhotoType, boolean allowCaption, ChatActivity chatActivity) {
        this.selectedAlbum = selectedAlbum;
        this.selectedPhotos = selectedPhotos;
        this.selectedPhotosOrder = selectedPhotosOrder;
        this.type = type;
        this.recentImages = recentImages != null ? recentImages : new ArrayList<>();
        this.selectPhotoType = selectPhotoType;
        this.chatActivity = chatActivity;
        this.allowCaption = allowCaption;
    }

    public PhotoPickerActivity(int type, MediaController.AlbumEntry selectedAlbum, HashMap<Object, Object> selectedPhotos, ArrayList<Object> selectedPhotosOrder, ArrayList<MediaController.SearchImage> recentImages, int selectPhotoType, boolean allowCaption, ChatActivity chatActivity, boolean isFcCrop) {
        this.selectedAlbum = selectedAlbum;
        this.selectedPhotos = selectedPhotos;
        this.selectedPhotosOrder = selectedPhotosOrder;
        this.type = type;
        this.recentImages = recentImages != null ? recentImages : new ArrayList<>();
        this.selectPhotoType = selectPhotoType;
        this.chatActivity = chatActivity;
        this.allowCaption = allowCaption;
        this.isFcCrop = isFcCrop;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.closeChats);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recentImagesDidLoad);
        if (this.selectedAlbum == null && this.recentImages.isEmpty()) {
            MessagesStorage.getInstance(this.currentAccount).loadWebRecent(this.type);
            this.loadingRecent = true;
        }
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recentImagesDidLoad);
        if (this.imageReqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.imageReqId, true);
            this.imageReqId = 0;
        }
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji != null) {
            editTextEmoji.onDestroy();
        }
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mblnSendOriginal = false;
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.actionBar.setTitleColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_dialogTextBlack), false);
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_dialogButtonSelector), false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        if (this.selectedAlbum != null) {
            this.actionBar.setTitle(this.selectedAlbum.bucketName);
        } else {
            int i = this.type;
            if (i == 0) {
                this.actionBar.setTitle(LocaleController.getString("SearchImagesTitle", R.string.SearchImagesTitle));
            } else if (i == 1) {
                this.actionBar.setTitle(LocaleController.getString("SearchGifsTitle", R.string.SearchGifsTitle));
            }
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PhotoPickerActivity.this.finishFragment();
                    return;
                }
                if (id == 0) {
                    if (!PhotoPickerActivity.this.mblnSendOriginal) {
                        PhotoPickerActivity.this.iv.setColorFilter((ColorFilter) null);
                        PhotoPickerActivity.this.iv.setImageResource(R.id.ic_checked_completed_user_info);
                    } else {
                        PhotoPickerActivity.this.iv.setColorFilter(Color.parseColor("#707070"));
                        PhotoPickerActivity.this.iv.setImageResource(R.id.ic_checked_false_completed_user_info);
                    }
                    PhotoPickerActivity.this.mblnSendOriginal = !r0.mblnSendOriginal;
                }
            }
        });
        ActionBarMenu actionBarMenuCreateMenu = this.actionBar.createMenu();
        if (this.selectPhotoType == 0) {
            LinearLayout linearLayout = new LinearLayout(context);
            this.iv = new ImageView(context);
            linearLayout.setGravity(16);
            this.iv.setColorFilter(Color.parseColor("#707070"));
            this.iv.setImageResource(R.id.ic_checked_false_completed_user_info);
            this.iv.setScaleType(ImageView.ScaleType.FIT_XY);
            linearLayout.addView(this.iv, LayoutHelper.createLinear(AndroidUtilities.dp(7.0f), AndroidUtilities.dp(7.0f), 0.0f, 0.0f, 0.0f, 0.0f));
            TextView tv = new TextView(context);
            tv.setText(LocaleController.getString(R.string.original_image));
            tv.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            linearLayout.addView(tv, LayoutHelper.createLinear(-2, -2, AndroidUtilities.dp(1.0f), 0.0f, 0.0f, 0.0f));
            actionBarMenuCreateMenu.addItemView(0, linearLayout);
        }
        if (this.selectedAlbum == null) {
            ActionBarMenu menu = this.actionBar.createMenu();
            ActionBarMenuItem actionBarMenuItemSearchListener = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.3
                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onSearchExpand() {
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public boolean canCollapseSearch() {
                    PhotoPickerActivity.this.finishFragment();
                    return false;
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onTextChanged(EditText editText) {
                    if (editText.getText().length() == 0) {
                        PhotoPickerActivity.this.searchResult.clear();
                        PhotoPickerActivity.this.searchResultKeys.clear();
                        PhotoPickerActivity.this.lastSearchString = null;
                        PhotoPickerActivity.this.imageSearchEndReached = true;
                        PhotoPickerActivity.this.searching = false;
                        if (PhotoPickerActivity.this.imageReqId != 0) {
                            ConnectionsManager.getInstance(PhotoPickerActivity.this.currentAccount).cancelRequest(PhotoPickerActivity.this.imageReqId, true);
                            PhotoPickerActivity.this.imageReqId = 0;
                        }
                        PhotoPickerActivity.this.emptyView.setText("");
                        PhotoPickerActivity.this.updateSearchInterface();
                        return;
                    }
                    PhotoPickerActivity.this.processSearch(editText);
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onSearchPressed(EditText editText) {
                    PhotoPickerActivity.this.processSearch(editText);
                }
            });
            this.searchItem = actionBarMenuItemSearchListener;
            EditTextBoldCursor editText = actionBarMenuItemSearchListener.getSearchField();
            editText.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            editText.setCursorColor(Theme.getColor(Theme.key_dialogTextBlack));
            editText.setHintTextColor(Theme.getColor(Theme.key_chat_messagePanelHint));
        }
        if (this.selectedAlbum == null) {
            int i2 = this.type;
            if (i2 == 0) {
                this.searchItem.setSearchFieldHint(LocaleController.getString("SearchImagesTitle", R.string.SearchImagesTitle));
            } else if (i2 == 1) {
                this.searchItem.setSearchFieldHint(LocaleController.getString("SearchGifsTitle", R.string.SearchGifsTitle));
            }
        }
        AnonymousClass4 anonymousClass4 = new AnonymousClass4(context);
        this.sizeNotifierFrameLayout = anonymousClass4;
        anonymousClass4.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.fragmentView = this.sizeNotifierFrameLayout;
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setPadding(AndroidUtilities.dp(6.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(6.0f), AndroidUtilities.dp(50.0f));
        this.listView.setClipToPadding(false);
        this.listView.setHorizontalScrollBarEnabled(false);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        RecyclerListView recyclerListView2 = this.listView;
        GridLayoutManager gridLayoutManager = new GridLayoutManager(context, 4) { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.5
            @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = gridLayoutManager;
        recyclerListView2.setLayoutManager(gridLayoutManager);
        this.layoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.6
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                return PhotoPickerActivity.this.itemSize + (position % PhotoPickerActivity.this.itemsPerRow != PhotoPickerActivity.this.itemsPerRow + (-1) ? AndroidUtilities.dp(5.0f) : 0);
            }
        });
        this.sizeNotifierFrameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, 51));
        RecyclerListView recyclerListView3 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listAdapter = listAdapter;
        recyclerListView3.setAdapter(listAdapter);
        this.listView.setGlowColor(Theme.getColor(Theme.key_dialogBackground));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$5D-vk1mj4gUr7OysWhJKysOcE6k
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i3) {
                this.f$0.lambda$createView$0$PhotoPickerActivity(view, i3);
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$7qcIXeLr3xEV7Kb3MzQoh2_Rdx4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i3) {
                return this.f$0.lambda$createView$1$PhotoPickerActivity(view, i3);
            }
        });
        RecyclerViewItemRangeSelector recyclerViewItemRangeSelector = new RecyclerViewItemRangeSelector(new RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.7
            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public int getItemCount() {
                return PhotoPickerActivity.this.listAdapter.getItemCount();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public void setSelected(View view, int index, boolean selected) {
                if (selected != PhotoPickerActivity.this.shouldSelect || !(view instanceof PhotoAttachPhotoCell)) {
                    return;
                }
                PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                cell.callDelegate();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public boolean isSelected(int index) {
                Object key;
                if (PhotoPickerActivity.this.selectedAlbum != null) {
                    MediaController.PhotoEntry photoEntry = PhotoPickerActivity.this.selectedAlbum.photos.get(index);
                    key = Integer.valueOf(photoEntry.imageId);
                } else {
                    MediaController.SearchImage photoEntry2 = (PhotoPickerActivity.this.searchResult.isEmpty() && PhotoPickerActivity.this.lastSearchString == null) ? (MediaController.SearchImage) PhotoPickerActivity.this.recentImages.get(index) : (MediaController.SearchImage) PhotoPickerActivity.this.searchResult.get(index);
                    key = photoEntry2.id;
                }
                return PhotoPickerActivity.this.selectedPhotos.containsKey(key);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public boolean isIndexSelectable(int index) {
                return PhotoPickerActivity.this.listAdapter.getItemViewType(index) == 0;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerViewItemRangeSelector.RecyclerViewItemRangeSelectorDelegate
            public void onStartStopSelection(boolean z) {
                PhotoPickerActivity.this.alertOnlyOnce = z ? 1 : 0;
                if (z) {
                    PhotoPickerActivity.this.parentLayout.requestDisallowInterceptTouchEvent(true);
                }
                PhotoPickerActivity.this.listView.hideSelector();
            }
        });
        this.itemRangeSelector = recyclerViewItemRangeSelector;
        this.listView.addOnItemTouchListener(recyclerViewItemRangeSelector);
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.setTextColor(-8355712);
        this.emptyView.setProgressBarColor(-11371101);
        this.emptyView.setShowAtCenter(false);
        if (this.selectedAlbum != null) {
            this.emptyView.setText(LocaleController.getString("NoPhotos", R.string.NoPhotos));
        } else {
            this.emptyView.setText("");
        }
        this.sizeNotifierFrameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, this.selectPhotoType != 0 ? 0.0f : 48.0f));
        if (this.selectedAlbum == null) {
            this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.8
                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                    if (newState == 1) {
                        AndroidUtilities.hideKeyboard(PhotoPickerActivity.this.getParentActivity().getCurrentFocus());
                    }
                }

                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                    int firstVisibleItem = PhotoPickerActivity.this.layoutManager.findFirstVisibleItemPosition();
                    int visibleItemCount = firstVisibleItem == -1 ? 0 : Math.abs(PhotoPickerActivity.this.layoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
                    if (visibleItemCount > 0) {
                        int totalItemCount = PhotoPickerActivity.this.layoutManager.getItemCount();
                        if (visibleItemCount != 0 && firstVisibleItem + visibleItemCount > totalItemCount - 2 && !PhotoPickerActivity.this.searching && !PhotoPickerActivity.this.imageSearchEndReached) {
                            PhotoPickerActivity photoPickerActivity = PhotoPickerActivity.this;
                            photoPickerActivity.searchImages(photoPickerActivity.type == 1, PhotoPickerActivity.this.lastSearchString, PhotoPickerActivity.this.nextImagesSearchOffset, true);
                        }
                    }
                }
            });
            updateSearchInterface();
        }
        if (this.needsBottomLayout) {
            View view = new View(context);
            this.shadow = view;
            view.setBackgroundResource(R.drawable.header_shadow_reverse);
            this.shadow.setTranslationY(AndroidUtilities.dp(48.0f));
            this.sizeNotifierFrameLayout.addView(this.shadow, LayoutHelper.createFrame(-1.0f, 3.0f, 83, 0.0f, 0.0f, 0.0f, 48.0f));
            FrameLayout frameLayout = new FrameLayout(context);
            this.frameLayout2 = frameLayout;
            frameLayout.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
            this.frameLayout2.setVisibility(4);
            this.frameLayout2.setTranslationY(AndroidUtilities.dp(48.0f));
            this.sizeNotifierFrameLayout.addView(this.frameLayout2, LayoutHelper.createFrame(-1, 48, 83));
            this.frameLayout2.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$EhJEBq4mTBpDeKzg54cedWhYGW4
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view2, MotionEvent motionEvent) {
                    return PhotoPickerActivity.lambda$createView$2(view2, motionEvent);
                }
            });
            EditTextEmoji editTextEmoji = this.commentTextView;
            if (editTextEmoji != null) {
                editTextEmoji.onDestroy();
            }
            this.commentTextView = new EditTextEmoji(context, this.sizeNotifierFrameLayout, null, 1);
            InputFilter[] inputFilters = {new InputFilter.LengthFilter(MessagesController.getInstance(UserConfig.selectedAccount).maxCaptionLength)};
            this.commentTextView.setFilters(inputFilters);
            this.commentTextView.setHint(LocaleController.getString("AddCaption", R.string.AddCaption));
            this.commentTextView.onResume();
            EditTextBoldCursor editText2 = this.commentTextView.getEditText();
            editText2.setMaxLines(1);
            editText2.setSingleLine(true);
            this.frameLayout2.addView(this.commentTextView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 84.0f, 0.0f));
            CharSequence charSequence = this.caption;
            if (charSequence != null) {
                this.commentTextView.setText(charSequence);
            }
            this.commentTextView.getEditText().addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.9
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    if (PhotoPickerActivity.this.delegate != null) {
                        PhotoPickerActivity.this.delegate.onCaptionChanged(s);
                    }
                }
            });
            FrameLayout frameLayout2 = new FrameLayout(context);
            this.writeButtonContainer = frameLayout2;
            frameLayout2.setVisibility(4);
            this.writeButtonContainer.setScaleX(0.2f);
            this.writeButtonContainer.setScaleY(0.2f);
            this.writeButtonContainer.setAlpha(0.0f);
            this.writeButtonContainer.setContentDescription(LocaleController.getString("Send", R.string.Send));
            this.sizeNotifierFrameLayout.addView(this.writeButtonContainer, LayoutHelper.createFrame(60.0f, 60.0f, 85, 0.0f, 0.0f, 6.0f, 10.0f));
            this.writeButtonContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$rfv6tQCyVKWnsgonPV0c2cWBEBo
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$3$PhotoPickerActivity(view2);
                }
            });
            this.writeButton = new ImageView(context);
            this.writeButtonDrawable = Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), Theme.getColor(Theme.key_dialogFloatingButton), Theme.getColor(Theme.key_dialogFloatingButtonPressed));
            if (Build.VERSION.SDK_INT < 21) {
                Drawable shadowDrawable = context.getResources().getDrawable(R.drawable.floating_shadow_profile).mutate();
                shadowDrawable.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
                CombinedDrawable combinedDrawable = new CombinedDrawable(shadowDrawable, this.writeButtonDrawable, 0, 0);
                combinedDrawable.setIconSize(AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
                this.writeButtonDrawable = combinedDrawable;
            }
            this.writeButton.setBackgroundDrawable(this.writeButtonDrawable);
            this.writeButton.setImageResource(R.drawable.attach_send);
            this.writeButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogFloatingIcon), PorterDuff.Mode.MULTIPLY));
            this.writeButton.setScaleType(ImageView.ScaleType.CENTER);
            if (Build.VERSION.SDK_INT >= 21) {
                this.writeButton.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.10
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view2, Outline outline) {
                        outline.setOval(0, 0, AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
                    }
                });
            }
            this.writeButtonContainer.addView(this.writeButton, LayoutHelper.createFrame(Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, 51, Build.VERSION.SDK_INT >= 21 ? 2.0f : 0.0f, 0.0f, 0.0f, 0.0f));
            this.textPaint.setTextSize(AndroidUtilities.dp(12.0f));
            this.textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            View view2 = new View(context) { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.11
                @Override // android.view.View
                protected void onDraw(Canvas canvas) {
                    String text = String.format("%d", Integer.valueOf(Math.max(1, PhotoPickerActivity.this.selectedPhotosOrder.size())));
                    int textSize = (int) Math.ceil(PhotoPickerActivity.this.textPaint.measureText(text));
                    int size = Math.max(AndroidUtilities.dp(16.0f) + textSize, AndroidUtilities.dp(24.0f));
                    int cx = getMeasuredWidth() / 2;
                    int measuredHeight = getMeasuredHeight() / 2;
                    PhotoPickerActivity.this.textPaint.setColor(Theme.getColor(Theme.key_dialogRoundCheckBoxCheck));
                    PhotoPickerActivity.this.paint.setColor(Theme.getColor(Theme.key_dialogBackground));
                    PhotoPickerActivity.this.rect.set(cx - (size / 2), 0.0f, (size / 2) + cx, getMeasuredHeight());
                    canvas.drawRoundRect(PhotoPickerActivity.this.rect, AndroidUtilities.dp(12.0f), AndroidUtilities.dp(12.0f), PhotoPickerActivity.this.paint);
                    PhotoPickerActivity.this.paint.setColor(Theme.getColor(Theme.key_dialogRoundCheckBox));
                    PhotoPickerActivity.this.rect.set((cx - (size / 2)) + AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), ((size / 2) + cx) - AndroidUtilities.dp(2.0f), getMeasuredHeight() - AndroidUtilities.dp(2.0f));
                    canvas.drawRoundRect(PhotoPickerActivity.this.rect, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), PhotoPickerActivity.this.paint);
                    canvas.drawText(text, cx - (textSize / 2), AndroidUtilities.dp(16.2f), PhotoPickerActivity.this.textPaint);
                }
            };
            this.selectedCountView = view2;
            view2.setAlpha(0.0f);
            this.selectedCountView.setScaleX(0.2f);
            this.selectedCountView.setScaleY(0.2f);
            this.sizeNotifierFrameLayout.addView(this.selectedCountView, LayoutHelper.createFrame(42.0f, 24.0f, 85, 0.0f, 0.0f, -8.0f, 9.0f));
            if (this.selectPhotoType != 0) {
                this.commentTextView.setVisibility(8);
            }
        }
        this.allowIndices = (this.selectedAlbum != null || this.type == 0) && this.allowOrder;
        this.listView.setEmptyView(this.emptyView);
        updatePhotosButton(0);
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoPickerActivity$4, reason: invalid class name */
    class AnonymousClass4 extends SizeNotifierFrameLayout {
        private boolean ignoreLayout;
        private int lastItemSize;
        private int lastNotifyWidth;

        AnonymousClass4(Context context) {
            super(context);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int totalHeight = View.MeasureSpec.getSize(heightMeasureSpec);
            int availableWidth = View.MeasureSpec.getSize(widthMeasureSpec);
            if (!AndroidUtilities.isTablet() && AndroidUtilities.displaySize.x <= AndroidUtilities.displaySize.y) {
                PhotoPickerActivity.this.itemsPerRow = 3;
            } else {
                PhotoPickerActivity.this.itemsPerRow = 4;
            }
            this.ignoreLayout = true;
            PhotoPickerActivity.this.itemSize = ((availableWidth - AndroidUtilities.dp(12.0f)) - AndroidUtilities.dp(10.0f)) / PhotoPickerActivity.this.itemsPerRow;
            if (this.lastItemSize != PhotoPickerActivity.this.itemSize) {
                this.lastItemSize = PhotoPickerActivity.this.itemSize;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$4$iv0G1qMBGfl65PNXBKJmRFFJEM8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onMeasure$0$PhotoPickerActivity$4();
                    }
                });
            }
            PhotoPickerActivity.this.layoutManager.setSpanCount((PhotoPickerActivity.this.itemSize * PhotoPickerActivity.this.itemsPerRow) + (AndroidUtilities.dp(5.0f) * (PhotoPickerActivity.this.itemsPerRow - 1)));
            this.ignoreLayout = false;
            onMeasureInternal(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(totalHeight, 1073741824));
        }

        public /* synthetic */ void lambda$onMeasure$0$PhotoPickerActivity$4() {
            PhotoPickerActivity.this.listAdapter.notifyDataSetChanged();
        }

        private void onMeasureInternal(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
            setMeasuredDimension(widthSize, heightSize);
            int keyboardSize = getKeyboardHeight();
            if (keyboardSize <= AndroidUtilities.dp(20.0f)) {
                if (!AndroidUtilities.isInMultiwindow && PhotoPickerActivity.this.commentTextView != null && PhotoPickerActivity.this.frameLayout2.getParent() == this) {
                    heightSize -= PhotoPickerActivity.this.commentTextView.getEmojiPadding();
                    heightMeasureSpec = View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824);
                }
            } else if (PhotoPickerActivity.this.commentTextView != null) {
                this.ignoreLayout = true;
                PhotoPickerActivity.this.commentTextView.hideEmojiView();
                this.ignoreLayout = false;
            }
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                if (child != null && child.getVisibility() != 8) {
                    if (PhotoPickerActivity.this.commentTextView != null && PhotoPickerActivity.this.commentTextView.isPopupView(child)) {
                        if (AndroidUtilities.isInMultiwindow || AndroidUtilities.isTablet()) {
                            if (AndroidUtilities.isTablet()) {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(Math.min(AndroidUtilities.dp(AndroidUtilities.isTablet() ? 200.0f : 320.0f), (heightSize - AndroidUtilities.statusBarHeight) + getPaddingTop()), 1073741824));
                            } else {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec((heightSize - AndroidUtilities.statusBarHeight) + getPaddingTop(), 1073741824));
                            }
                        } else {
                            child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(child.getLayoutParams().height, 1073741824));
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
                if (PhotoPickerActivity.this.listAdapter != null) {
                    PhotoPickerActivity.this.listAdapter.notifyDataSetChanged();
                }
                if (PhotoPickerActivity.this.sendPopupWindow != null && PhotoPickerActivity.this.sendPopupWindow.isShowing()) {
                    PhotoPickerActivity.this.sendPopupWindow.dismiss();
                }
            }
            int count = getChildCount();
            int paddingBottom = (PhotoPickerActivity.this.commentTextView == null || PhotoPickerActivity.this.frameLayout2.getParent() != this || getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow || AndroidUtilities.isTablet()) ? 0 : PhotoPickerActivity.this.commentTextView.getEmojiPadding();
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
                        childLeft = ((childLeft3 - width) - lp.rightMargin) - getPaddingRight();
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
                    if (PhotoPickerActivity.this.commentTextView != null && PhotoPickerActivity.this.commentTextView.isPopupView(child)) {
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
        }

        @Override // android.view.View, android.view.ViewParent
        public void requestLayout() {
            if (this.ignoreLayout) {
                return;
            }
            super.requestLayout();
        }
    }

    public /* synthetic */ void lambda$createView$0$PhotoPickerActivity(View view, int position) {
        ArrayList<Object> arrayList;
        int type;
        MediaController.AlbumEntry albumEntry = this.selectedAlbum;
        if (albumEntry != null) {
            arrayList = albumEntry.photos;
        } else {
            ArrayList<Object> arrayList2 = this.searchResult;
            if (arrayList2.isEmpty() && this.lastSearchString == null) {
                arrayList = this.recentImages;
            } else {
                arrayList = this.searchResult;
            }
        }
        if (position < 0 || position >= arrayList.size()) {
            return;
        }
        ActionBarMenuItem actionBarMenuItem = this.searchItem;
        if (actionBarMenuItem != null) {
            AndroidUtilities.hideKeyboard(actionBarMenuItem.getSearchField());
        }
        int i = this.selectPhotoType;
        if (i == 1) {
            type = 1;
        } else if (i == 2) {
            type = 3;
        } else if (this.chatActivity == null) {
            type = 4;
        } else {
            type = 0;
        }
        PhotoViewer.getInstance().setParentActivity(getParentActivity());
        PhotoViewer.getInstance().setMaxSelectedPhotos(this.maxSelectedPhotos, this.allowOrder);
        if (this.isFcCrop) {
            PhotoViewer.getInstance().setIsFcCrop(true);
            PhotoViewer.getInstance().openPhotoForSelect(arrayList, position, 1, this.provider, this.chatActivity);
        } else {
            PhotoViewer.getInstance().setIsFcCrop(false);
            PhotoViewer.getInstance().openPhotoForSelect(arrayList, position, type, this.provider, this.chatActivity);
        }
    }

    public /* synthetic */ boolean lambda$createView$1$PhotoPickerActivity(View view, int position) {
        if (!this.isFcCrop && (view instanceof PhotoAttachPhotoCell)) {
            PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
            RecyclerViewItemRangeSelector recyclerViewItemRangeSelector = this.itemRangeSelector;
            boolean z = !cell.isChecked();
            this.shouldSelect = z;
            recyclerViewItemRangeSelector.setIsActive(view, true, position, z);
            return false;
        }
        return false;
    }

    static /* synthetic */ boolean lambda$createView$2(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$3$PhotoPickerActivity(View v) {
        ChatActivity chatActivity = this.chatActivity;
        if (chatActivity != null && chatActivity.isInScheduleMode()) {
            AlertsCreator.createScheduleDatePickerDialog(getParentActivity(), UserObject.isUserSelf(this.chatActivity.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$aCAUJIOK9Jr_dZl9yVrMndZ92Wk
                @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                public final void didSelectDate(boolean z, int i) {
                    this.f$0.sendSelectedPhotos(z, i);
                }
            });
        } else {
            sendSelectedPhotos(true, 0);
        }
    }

    public void setLayoutViews(FrameLayout f2, FrameLayout button, View count, View s, EditTextEmoji emoji) {
        this.frameLayout2 = f2;
        this.writeButtonContainer = button;
        this.commentTextView = emoji;
        this.selectedCountView = count;
        this.shadow = s;
        this.needsBottomLayout = false;
    }

    private void applyCaption() {
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji == null || editTextEmoji.length() <= 0) {
            return;
        }
        Object imageId = this.selectedPhotosOrder.get(0);
        Object entry = this.selectedPhotos.get(imageId);
        if (entry instanceof MediaController.PhotoEntry) {
            MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) entry;
            photoEntry.caption = this.commentTextView.getText().toString();
        } else if (entry instanceof MediaController.SearchImage) {
            MediaController.SearchImage searchImage = (MediaController.SearchImage) entry;
            searchImage.caption = this.commentTextView.getText().toString();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji != null) {
            editTextEmoji.onResume();
        }
        ActionBarMenuItem actionBarMenuItem = this.searchItem;
        if (actionBarMenuItem != null) {
            actionBarMenuItem.openSearch(true);
            if (!TextUtils.isEmpty(this.initialSearchString)) {
                this.searchItem.setSearchFieldText(this.initialSearchString, false);
                this.initialSearchString = null;
                processSearch(this.searchItem.getSearchField());
            }
            getParentActivity().getWindow().setSoftInputMode(16);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.closeChats) {
            removeSelfFromStack();
            return;
        }
        if (id == NotificationCenter.recentImagesDidLoad && this.selectedAlbum == null && this.type == ((Integer) args[0]).intValue()) {
            this.recentImages = (ArrayList) args[1];
            this.loadingRecent = false;
            updateSearchInterface();
        }
    }

    public RecyclerListView getListView() {
        return this.listView;
    }

    public void setCaption(CharSequence text) {
        this.caption = text;
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji != null) {
            editTextEmoji.setText(text);
        }
    }

    public void setInitialSearchString(String text) {
        this.initialSearchString = text;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processSearch(EditText editText) {
        if (editText.getText().toString().length() == 0) {
            return;
        }
        this.searchResult.clear();
        this.searchResultKeys.clear();
        this.imageSearchEndReached = true;
        searchImages(this.type == 1, editText.getText().toString(), "", true);
        String string = editText.getText().toString();
        this.lastSearchString = string;
        if (string.length() == 0) {
            this.lastSearchString = null;
            this.emptyView.setText("");
        } else {
            this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
        }
        updateSearchInterface();
    }

    private boolean showCommentTextView(final boolean show, boolean animated) {
        if (this.commentTextView == null) {
            return false;
        }
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
            FrameLayout frameLayout = this.writeButtonContainer;
            Property property = View.SCALE_X;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.2f;
            animators.add(ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property, fArr));
            FrameLayout frameLayout2 = this.writeButtonContainer;
            Property property2 = View.SCALE_Y;
            float[] fArr2 = new float[1];
            fArr2[0] = show ? 1.0f : 0.2f;
            animators.add(ObjectAnimator.ofFloat(frameLayout2, (Property<FrameLayout, Float>) property2, fArr2));
            FrameLayout frameLayout3 = this.writeButtonContainer;
            Property property3 = View.ALPHA;
            float[] fArr3 = new float[1];
            fArr3[0] = show ? 1.0f : 0.0f;
            animators.add(ObjectAnimator.ofFloat(frameLayout3, (Property<FrameLayout, Float>) property3, fArr3));
            View view = this.selectedCountView;
            Property property4 = View.SCALE_X;
            float[] fArr4 = new float[1];
            fArr4[0] = show ? 1.0f : 0.2f;
            animators.add(ObjectAnimator.ofFloat(view, (Property<View, Float>) property4, fArr4));
            View view2 = this.selectedCountView;
            Property property5 = View.SCALE_Y;
            float[] fArr5 = new float[1];
            fArr5[0] = show ? 1.0f : 0.2f;
            animators.add(ObjectAnimator.ofFloat(view2, (Property<View, Float>) property5, fArr5));
            View view3 = this.selectedCountView;
            Property property6 = View.ALPHA;
            float[] fArr6 = new float[1];
            fArr6[0] = show ? 1.0f : 0.0f;
            animators.add(ObjectAnimator.ofFloat(view3, (Property<View, Float>) property6, fArr6));
            FrameLayout frameLayout4 = this.frameLayout2;
            Property property7 = View.TRANSLATION_Y;
            float[] fArr7 = new float[1];
            fArr7[0] = show ? 0.0f : AndroidUtilities.dp(48.0f);
            animators.add(ObjectAnimator.ofFloat(frameLayout4, (Property<FrameLayout, Float>) property7, fArr7));
            View view4 = this.shadow;
            Property property8 = View.TRANSLATION_Y;
            float[] fArr8 = new float[1];
            fArr8[0] = show ? 0.0f : AndroidUtilities.dp(48.0f);
            animators.add(ObjectAnimator.ofFloat(view4, (Property<View, Float>) property8, fArr8));
            this.animatorSet.playTogether(animators);
            this.animatorSet.setInterpolator(new DecelerateInterpolator());
            this.animatorSet.setDuration(180L);
            this.animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.12
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(PhotoPickerActivity.this.animatorSet)) {
                        if (!show) {
                            PhotoPickerActivity.this.frameLayout2.setVisibility(4);
                            PhotoPickerActivity.this.writeButtonContainer.setVisibility(4);
                        }
                        PhotoPickerActivity.this.animatorSet = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (animation.equals(PhotoPickerActivity.this.animatorSet)) {
                        PhotoPickerActivity.this.animatorSet = null;
                    }
                }
            });
            this.animatorSet.start();
        } else {
            this.writeButtonContainer.setScaleX(show ? 1.0f : 0.2f);
            this.writeButtonContainer.setScaleY(show ? 1.0f : 0.2f);
            this.writeButtonContainer.setAlpha(show ? 1.0f : 0.0f);
            this.selectedCountView.setScaleX(show ? 1.0f : 0.2f);
            this.selectedCountView.setScaleY(show ? 1.0f : 0.2f);
            this.selectedCountView.setAlpha(show ? 1.0f : 0.0f);
            this.frameLayout2.setTranslationY(show ? 0.0f : AndroidUtilities.dp(48.0f));
            this.shadow.setTranslationY(show ? 0.0f : AndroidUtilities.dp(48.0f));
            if (!show) {
                this.frameLayout2.setVisibility(4);
                this.writeButtonContainer.setVisibility(4);
            }
        }
        return true;
    }

    public void setMaxSelectedPhotos(int value, boolean order) {
        this.maxSelectedPhotos = value;
        this.allowOrder = order;
        if (value > 0 && this.type == 1) {
            this.maxSelectedPhotos = 1;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateCheckedPhotoIndices() {
        MediaController.SearchImage photoEntry;
        if (!this.allowIndices) {
            return;
        }
        int count = this.listView.getChildCount();
        for (int a = 0; a < count; a++) {
            View view = this.listView.getChildAt(a);
            if (view instanceof PhotoAttachPhotoCell) {
                PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) view;
                Integer index = (Integer) cell.getTag();
                MediaController.AlbumEntry albumEntry = this.selectedAlbum;
                if (albumEntry != null) {
                    MediaController.PhotoEntry photoEntry2 = albumEntry.photos.get(index.intValue());
                    cell.setNum(this.allowIndices ? this.selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry2.imageId)) : -1);
                } else {
                    if (this.searchResult.isEmpty() && this.lastSearchString == null) {
                        photoEntry = this.recentImages.get(index.intValue());
                    } else {
                        photoEntry = this.searchResult.get(index.intValue());
                    }
                    cell.setNum(this.allowIndices ? this.selectedPhotosOrder.indexOf(photoEntry.id) : -1);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0049  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell getCellForIndex(int r8) {
        /*
            r7 = this;
            im.uwrkaxlmjj.ui.components.RecyclerListView r0 = r7.listView
            int r0 = r0.getChildCount()
            r1 = 0
        L7:
            if (r1 >= r0) goto L4f
            im.uwrkaxlmjj.ui.components.RecyclerListView r2 = r7.listView
            android.view.View r2 = r2.getChildAt(r1)
            boolean r3 = r2 instanceof im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell
            if (r3 == 0) goto L4c
            r3 = r2
            im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell r3 = (im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell) r3
            java.lang.Object r4 = r3.getTag()
            java.lang.Integer r4 = (java.lang.Integer) r4
            int r4 = r4.intValue()
            im.uwrkaxlmjj.messenger.MediaController$AlbumEntry r5 = r7.selectedAlbum
            if (r5 == 0) goto L2f
            if (r4 < 0) goto L4c
            java.util.ArrayList<im.uwrkaxlmjj.messenger.MediaController$PhotoEntry> r5 = r5.photos
            int r5 = r5.size()
            if (r4 < r5) goto L49
            goto L4c
        L2f:
            java.util.ArrayList<im.uwrkaxlmjj.messenger.MediaController$SearchImage> r5 = r7.searchResult
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L3e
            java.lang.String r5 = r7.lastSearchString
            if (r5 != 0) goto L3e
            java.util.ArrayList<im.uwrkaxlmjj.messenger.MediaController$SearchImage> r5 = r7.recentImages
            goto L40
        L3e:
            java.util.ArrayList<im.uwrkaxlmjj.messenger.MediaController$SearchImage> r5 = r7.searchResult
        L40:
            if (r4 < 0) goto L4c
            int r6 = r5.size()
            if (r4 < r6) goto L49
            goto L4c
        L49:
            if (r4 != r8) goto L4c
            return r3
        L4c:
            int r1 = r1 + 1
            goto L7
        L4f:
            r1 = 0
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PhotoPickerActivity.getCellForIndex(int):im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int addToSelectedPhotos(Object object, int index) {
        Object key = null;
        if (object instanceof MediaController.PhotoEntry) {
            key = Integer.valueOf(((MediaController.PhotoEntry) object).imageId);
        } else if (object instanceof MediaController.SearchImage) {
            key = ((MediaController.SearchImage) object).id;
        }
        if (key == null) {
            return -1;
        }
        if (this.selectedPhotos.containsKey(key)) {
            this.selectedPhotos.remove(key);
            int position = this.selectedPhotosOrder.indexOf(key);
            if (position >= 0) {
                this.selectedPhotosOrder.remove(position);
            }
            if (this.allowIndices) {
                updateCheckedPhotoIndices();
            }
            if (index >= 0) {
                if (object instanceof MediaController.PhotoEntry) {
                    ((MediaController.PhotoEntry) object).reset();
                } else if (object instanceof MediaController.SearchImage) {
                    ((MediaController.SearchImage) object).reset();
                }
                this.provider.updatePhotoAtIndex(index);
            }
            return position;
        }
        this.selectedPhotos.put(key, object);
        this.selectedPhotosOrder.add(key);
        return -1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        ActionBarMenuItem actionBarMenuItem;
        if (isOpen && (actionBarMenuItem = this.searchItem) != null) {
            AndroidUtilities.showKeyboard(actionBarMenuItem.getSearchField());
        }
    }

    public void updatePhotosButton(int animated) {
        int count = this.selectedPhotos.size();
        if (count == 0) {
            this.selectedCountView.setPivotX(0.0f);
            this.selectedCountView.setPivotY(0.0f);
            showCommentTextView(false, animated != 0);
            return;
        }
        this.selectedCountView.invalidate();
        if (showCommentTextView(true, animated != 0) || animated == 0) {
            this.selectedCountView.setPivotX(0.0f);
            this.selectedCountView.setPivotY(0.0f);
            return;
        }
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
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSearchInterface() {
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        if ((this.searching && this.searchResult.isEmpty()) || (this.loadingRecent && this.lastSearchString == null)) {
            this.emptyView.showProgress();
        } else {
            this.emptyView.showTextView();
        }
    }

    private void searchBotUser(final boolean gif) {
        if (this.searchingUser) {
            return;
        }
        this.searchingUser = true;
        TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
        MessagesController messagesController = MessagesController.getInstance(this.currentAccount);
        req.username = gif ? messagesController.gifSearchBot : messagesController.imageSearchBot;
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$hLHVpn_0izRyBWeduatxwyugQtc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$searchBotUser$5$PhotoPickerActivity(gif, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$searchBotUser$5$PhotoPickerActivity(final boolean gif, final TLObject response, TLRPC.TL_error error) {
        this.searchingUser = false;
        if (response != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$NLfUhvYtSIywzFietqj6_o4Jy4s
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$4$PhotoPickerActivity(response, gif);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$4$PhotoPickerActivity(TLObject response, boolean gif) {
        TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
        MessagesController.getInstance(this.currentAccount).putUsers(res.users, false);
        MessagesController.getInstance(this.currentAccount).putChats(res.chats, false);
        MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(res.users, res.chats, true, true);
        String str = this.lastSearchImageString;
        this.lastSearchImageString = null;
        searchImages(gif, str, "", false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void searchImages(final boolean gif, String query, String offset, boolean searchUser) {
        if (this.searching) {
            this.searching = false;
            if (this.imageReqId != 0) {
                ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.imageReqId, true);
                this.imageReqId = 0;
            }
        }
        this.lastSearchImageString = query;
        this.searching = true;
        MessagesController messagesController = MessagesController.getInstance(this.currentAccount);
        MessagesController messagesController2 = MessagesController.getInstance(this.currentAccount);
        TLObject object = messagesController.getUserOrChat(gif ? messagesController2.gifSearchBot : messagesController2.imageSearchBot);
        if (!(object instanceof TLRPC.User)) {
            if (searchUser) {
                searchBotUser(gif);
                return;
            }
            return;
        }
        final TLRPC.User user = (TLRPC.User) object;
        TLRPC.TL_messages_getInlineBotResults req = new TLRPC.TL_messages_getInlineBotResults();
        req.query = query == null ? "" : query;
        req.bot = MessagesController.getInstance(this.currentAccount).getInputUser(user);
        req.offset = offset;
        ChatActivity chatActivity = this.chatActivity;
        if (chatActivity != null) {
            long dialogId = chatActivity.getDialogId();
            int lower_id = (int) dialogId;
            if (lower_id != 0) {
                req.peer = MessagesController.getInstance(this.currentAccount).getInputPeer(lower_id);
            } else {
                req.peer = new TLRPC.TL_inputPeerEmpty();
            }
        } else {
            req.peer = new TLRPC.TL_inputPeerEmpty();
        }
        final int token = this.lastSearchToken + 1;
        this.lastSearchToken = token;
        this.imageReqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$TEAwxWOrxkgHtiH7ZnB8GHY34ZE
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$searchImages$7$PhotoPickerActivity(token, gif, user, tLObject, tL_error);
            }
        });
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(this.imageReqId, this.classGuid);
    }

    public /* synthetic */ void lambda$searchImages$7$PhotoPickerActivity(final int token, final boolean gif, final TLRPC.User user, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoPickerActivity$pz0R8xw8ilvW-yYLJobmbTwUsb0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$6$PhotoPickerActivity(token, response, gif, user);
            }
        });
    }

    public /* synthetic */ void lambda$null$6$PhotoPickerActivity(int i, TLObject tLObject, boolean z, TLRPC.User user) {
        TLRPC.PhotoSize closestPhotoSizeWithSize;
        if (i != this.lastSearchToken) {
            return;
        }
        int i2 = 0;
        int size = this.searchResult.size();
        if (tLObject != null) {
            TLRPC.messages_BotResults messages_botresults = (TLRPC.messages_BotResults) tLObject;
            this.nextImagesSearchOffset = messages_botresults.next_offset;
            int size2 = messages_botresults.results.size();
            for (int i3 = 0; i3 < size2; i3++) {
                TLRPC.BotInlineResult botInlineResult = messages_botresults.results.get(i3);
                if ((z || "photo".equals(botInlineResult.type)) && ((!z || "gif".equals(botInlineResult.type)) && !this.searchResultKeys.containsKey(botInlineResult.id))) {
                    MediaController.SearchImage searchImage = new MediaController.SearchImage();
                    if (z && botInlineResult.document != null) {
                        for (int i4 = 0; i4 < botInlineResult.document.attributes.size(); i4++) {
                            TLRPC.DocumentAttribute documentAttribute = botInlineResult.document.attributes.get(i4);
                            if ((documentAttribute instanceof TLRPC.TL_documentAttributeImageSize) || (documentAttribute instanceof TLRPC.TL_documentAttributeVideo)) {
                                searchImage.width = documentAttribute.w;
                                searchImage.height = documentAttribute.h;
                                break;
                            }
                        }
                        searchImage.document = botInlineResult.document;
                        searchImage.size = 0;
                        if (botInlineResult.photo != null && botInlineResult.document != null && (closestPhotoSizeWithSize = FileLoader.getClosestPhotoSizeWithSize(botInlineResult.photo.sizes, this.itemSize, true)) != null) {
                            botInlineResult.document.thumbs.add(closestPhotoSizeWithSize);
                            botInlineResult.document.flags |= 1;
                        }
                    } else if (!z && botInlineResult.photo != null) {
                        TLRPC.PhotoSize closestPhotoSizeWithSize2 = FileLoader.getClosestPhotoSizeWithSize(botInlineResult.photo.sizes, AndroidUtilities.getPhotoSize());
                        TLRPC.PhotoSize closestPhotoSizeWithSize3 = FileLoader.getClosestPhotoSizeWithSize(botInlineResult.photo.sizes, 320);
                        if (closestPhotoSizeWithSize2 != null) {
                            searchImage.width = closestPhotoSizeWithSize2.w;
                            searchImage.height = closestPhotoSizeWithSize2.h;
                            searchImage.photoSize = closestPhotoSizeWithSize2;
                            searchImage.photo = botInlineResult.photo;
                            searchImage.size = closestPhotoSizeWithSize2.size;
                            searchImage.thumbPhotoSize = closestPhotoSizeWithSize3;
                        }
                    } else if (botInlineResult.content != null) {
                        int i5 = 0;
                        while (true) {
                            if (i5 >= botInlineResult.content.attributes.size()) {
                                break;
                            }
                            TLRPC.DocumentAttribute documentAttribute2 = botInlineResult.content.attributes.get(i5);
                            if (!(documentAttribute2 instanceof TLRPC.TL_documentAttributeImageSize)) {
                                i5++;
                            } else {
                                searchImage.width = documentAttribute2.w;
                                searchImage.height = documentAttribute2.h;
                                break;
                            }
                        }
                        if (botInlineResult.thumb != null) {
                            searchImage.thumbUrl = botInlineResult.thumb.url;
                        } else {
                            searchImage.thumbUrl = null;
                        }
                        searchImage.imageUrl = botInlineResult.content.url;
                        searchImage.size = z ? 0 : botInlineResult.content.size;
                    }
                    searchImage.id = botInlineResult.id;
                    searchImage.type = z ? 1 : 0;
                    searchImage.inlineResult = botInlineResult;
                    searchImage.params = new HashMap<>();
                    searchImage.params.put(TtmlNode.ATTR_ID, botInlineResult.id);
                    searchImage.params.put("query_id", "" + messages_botresults.query_id);
                    searchImage.params.put("bot_name", user.username);
                    this.searchResult.add(searchImage);
                    this.searchResultKeys.put(searchImage.id, searchImage);
                    i2++;
                }
            }
            this.imageSearchEndReached = size == this.searchResult.size() || this.nextImagesSearchOffset == null;
        }
        this.searching = false;
        if (i2 != 0) {
            this.listAdapter.notifyItemRangeInserted(size, i2);
        } else if (this.imageSearchEndReached) {
            this.listAdapter.notifyItemRemoved(this.searchResult.size() - 1);
        }
        if ((this.searching && this.searchResult.isEmpty()) || (this.loadingRecent && this.lastSearchString == null)) {
            this.emptyView.showProgress();
        } else {
            this.emptyView.showTextView();
        }
    }

    public void setDelegate(PhotoPickerActivityDelegate delegate) {
        this.delegate = delegate;
    }

    public void setFCDelegate(FCPhotoPickerActivityDelegate mFCPhotoPickerActivityDelegate) {
        this.mFCPhotoPickerActivityDelegate = mFCPhotoPickerActivityDelegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendSelectedPhotos(boolean notify, int scheduleDate) {
        if (this.selectedPhotos.isEmpty() || this.delegate == null || this.sendPressed) {
            return;
        }
        applyCaption();
        this.sendPressed = true;
        this.delegate.actionButtonPressed(false, notify, scheduleDate, this.mblnSendOriginal);
        if (this.selectPhotoType != 2) {
            finishFragment();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            if (PhotoPickerActivity.this.selectedAlbum != null) {
                return true;
            }
            int position = holder.getAdapterPosition();
            return (PhotoPickerActivity.this.searchResult.isEmpty() && PhotoPickerActivity.this.lastSearchString == null) ? position < PhotoPickerActivity.this.recentImages.size() : position < PhotoPickerActivity.this.searchResult.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (PhotoPickerActivity.this.selectedAlbum == null) {
                if (!PhotoPickerActivity.this.searchResult.isEmpty()) {
                    return PhotoPickerActivity.this.searchResult.size() + (!PhotoPickerActivity.this.imageSearchEndReached ? 1 : 0);
                }
                return 0;
            }
            return PhotoPickerActivity.this.selectedAlbum.photos.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public long getItemId(int i) {
            return i;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                PhotoAttachPhotoCell cell = new PhotoAttachPhotoCell(this.mContext);
                cell.setDelegate(new PhotoAttachPhotoCell.PhotoAttachPhotoCellDelegate() { // from class: im.uwrkaxlmjj.ui.PhotoPickerActivity.ListAdapter.1
                    private void checkSlowMode() {
                        TLRPC.Chat chat;
                        if (PhotoPickerActivity.this.allowOrder && PhotoPickerActivity.this.chatActivity != null && (chat = PhotoPickerActivity.this.chatActivity.getCurrentChat()) != null && !ChatObject.hasAdminRights(chat) && chat.slowmode_enabled && PhotoPickerActivity.this.alertOnlyOnce != 2) {
                            AlertsCreator.showSimpleAlert(PhotoPickerActivity.this, LocaleController.getString("Slowmode", R.string.Slowmode), LocaleController.getString("SlowmodeSelectSendError", R.string.SlowmodeSelectSendError));
                            if (PhotoPickerActivity.this.alertOnlyOnce == 1) {
                                PhotoPickerActivity.this.alertOnlyOnce = 2;
                            }
                        }
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell.PhotoAttachPhotoCellDelegate
                    public void onCheckClick(PhotoAttachPhotoCell v) {
                        boolean added;
                        int index = ((Integer) v.getTag()).intValue();
                        int num = -1;
                        if (PhotoPickerActivity.this.selectedAlbum != null) {
                            MediaController.PhotoEntry photoEntry = PhotoPickerActivity.this.selectedAlbum.photos.get(index);
                            added = !PhotoPickerActivity.this.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId));
                            if (!added || PhotoPickerActivity.this.maxSelectedPhotos <= 0 || PhotoPickerActivity.this.selectedPhotos.size() < PhotoPickerActivity.this.maxSelectedPhotos) {
                                if (PhotoPickerActivity.this.allowIndices && added) {
                                    num = PhotoPickerActivity.this.selectedPhotosOrder.size();
                                }
                                v.setChecked(num, added, true);
                                PhotoPickerActivity.this.addToSelectedPhotos(photoEntry, index);
                            } else {
                                checkSlowMode();
                                return;
                            }
                        } else {
                            AndroidUtilities.hideKeyboard(PhotoPickerActivity.this.getParentActivity().getCurrentFocus());
                            MediaController.SearchImage photoEntry2 = (PhotoPickerActivity.this.searchResult.isEmpty() && PhotoPickerActivity.this.lastSearchString == null) ? (MediaController.SearchImage) PhotoPickerActivity.this.recentImages.get(index) : (MediaController.SearchImage) PhotoPickerActivity.this.searchResult.get(index);
                            added = !PhotoPickerActivity.this.selectedPhotos.containsKey(photoEntry2.id);
                            if (!added || PhotoPickerActivity.this.maxSelectedPhotos <= 0 || PhotoPickerActivity.this.selectedPhotos.size() < PhotoPickerActivity.this.maxSelectedPhotos) {
                                if (PhotoPickerActivity.this.allowIndices && added) {
                                    num = PhotoPickerActivity.this.selectedPhotosOrder.size();
                                }
                                v.setChecked(num, added, true);
                                PhotoPickerActivity.this.addToSelectedPhotos(photoEntry2, index);
                            } else {
                                checkSlowMode();
                                return;
                            }
                        }
                        PhotoPickerActivity.this.updatePhotosButton(added ? 1 : 2);
                        PhotoPickerActivity.this.delegate.selectedPhotosChanged();
                    }
                });
                cell.getCheckFrame().setVisibility(PhotoPickerActivity.this.selectPhotoType != 0 ? 8 : 0);
                view = cell;
            } else {
                FrameLayout frameLayout = new FrameLayout(this.mContext);
                view = frameLayout;
                RadialProgressView progressBar = new RadialProgressView(this.mContext);
                progressBar.setProgressColor(-11371101);
                frameLayout.addView(progressBar, LayoutHelper.createFrame(-1, -1.0f));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            boolean showing;
            ViewGroup.LayoutParams params;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                PhotoAttachPhotoCell cell = (PhotoAttachPhotoCell) holder.itemView;
                cell.setItemSize(PhotoPickerActivity.this.itemSize);
                BackupImageView imageView = cell.getImageView();
                cell.setTag(Integer.valueOf(position));
                imageView.setOrientation(0, true);
                if (PhotoPickerActivity.this.selectedAlbum != null) {
                    MediaController.PhotoEntry photoEntry = PhotoPickerActivity.this.selectedAlbum.photos.get(position);
                    cell.setPhotoEntry(photoEntry, true, false);
                    cell.setChecked(PhotoPickerActivity.this.allowIndices ? PhotoPickerActivity.this.selectedPhotosOrder.indexOf(Integer.valueOf(photoEntry.imageId)) : -1, PhotoPickerActivity.this.selectedPhotos.containsKey(Integer.valueOf(photoEntry.imageId)), false);
                    showing = PhotoViewer.isShowingImage(photoEntry.path);
                } else {
                    MediaController.SearchImage photoEntry2 = (PhotoPickerActivity.this.searchResult.isEmpty() && PhotoPickerActivity.this.lastSearchString == null) ? (MediaController.SearchImage) PhotoPickerActivity.this.recentImages.get(position) : (MediaController.SearchImage) PhotoPickerActivity.this.searchResult.get(position);
                    cell.setPhotoEntry(photoEntry2, true, false);
                    cell.getVideoInfoContainer().setVisibility(4);
                    cell.setChecked(PhotoPickerActivity.this.allowIndices ? PhotoPickerActivity.this.selectedPhotosOrder.indexOf(photoEntry2.id) : -1, PhotoPickerActivity.this.selectedPhotos.containsKey(photoEntry2.id), false);
                    showing = PhotoViewer.isShowingImage(photoEntry2.getPathToAttach());
                }
                imageView.getImageReceiver().setVisible(!showing, true);
                cell.getCheckBox().setVisibility((PhotoPickerActivity.this.selectPhotoType != 0 || showing) ? 8 : 0);
                return;
            }
            if (itemViewType == 1 && (params = holder.itemView.getLayoutParams()) != null) {
                params.width = PhotoPickerActivity.this.itemSize;
                params.height = PhotoPickerActivity.this.itemSize;
                holder.itemView.setLayoutParams(params);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (PhotoPickerActivity.this.selectedAlbum == null) {
                if ((PhotoPickerActivity.this.searchResult.isEmpty() && PhotoPickerActivity.this.lastSearchString == null && i < PhotoPickerActivity.this.recentImages.size()) || i < PhotoPickerActivity.this.searchResult.size()) {
                    return 0;
                }
                return 1;
            }
            return 0;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription[] themeDescriptionArr = new ThemeDescription[11];
        themeDescriptionArr[0] = new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_dialogBackground);
        themeDescriptionArr[1] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_dialogBackground);
        themeDescriptionArr[2] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_dialogTextBlack);
        themeDescriptionArr[3] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_dialogTextBlack);
        themeDescriptionArr[4] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_dialogButtonSelector);
        themeDescriptionArr[5] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_dialogTextBlack);
        themeDescriptionArr[6] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_chat_messagePanelHint);
        ActionBarMenuItem actionBarMenuItem = this.searchItem;
        themeDescriptionArr[7] = new ThemeDescription(actionBarMenuItem != null ? actionBarMenuItem.getSearchField() : null, ThemeDescription.FLAG_CURSORCOLOR, null, null, null, null, Theme.key_dialogTextBlack);
        themeDescriptionArr[8] = new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_dialogBackground);
        themeDescriptionArr[9] = new ThemeDescription(this.listView, 0, new Class[]{View.class}, null, new Drawable[]{Theme.chat_attachEmptyDrawable}, null, Theme.key_chat_attachEmptyImage);
        themeDescriptionArr[10] = new ThemeDescription(this.listView, 0, new Class[]{View.class}, null, null, null, Theme.key_chat_attachPhotoBackground);
        return themeDescriptionArr;
    }
}
