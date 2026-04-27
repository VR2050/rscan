package im.uwrkaxlmjj.ui.components;

import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.exifinterface.media.ExifInterface;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity;
import im.uwrkaxlmjj.ui.PhotoCropActivity;
import im.uwrkaxlmjj.ui.PhotoPickerActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class ImageUpdater implements NotificationCenter.NotificationCenterDelegate, PhotoCropActivity.PhotoEditActivityDelegate {
    private TLRPC.PhotoSize bigPhoto;
    private boolean clearAfterUpdate;
    public String currentPicturePath;
    public ImageUpdaterDelegate delegate;
    private String finalPath;
    public BaseFragment parentFragment;
    private TLRPC.PhotoSize smallPhoto;
    public String uploadingImage;
    private int currentAccount = UserConfig.selectedAccount;
    private File picturePath = null;
    private boolean searchAvailable = true;
    private boolean uploadAfterSelect = true;
    private ImageReceiver imageReceiver = new ImageReceiver(null);

    public interface ImageUpdaterDelegate {
        void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> arrayList, boolean z, int i);

        void didUploadPhoto(TLRPC.InputFile inputFile, TLRPC.PhotoSize photoSize, TLRPC.PhotoSize photoSize2);

        String getInitialSearchString();

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.ImageUpdater$ImageUpdaterDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static void $default$didSelectPhotos(ImageUpdaterDelegate _this, ArrayList arrayList, boolean notify, int scheduleDate) {
            }

            public static String $default$getInitialSearchString(ImageUpdaterDelegate _this) {
                return null;
            }
        }
    }

    public void clear() {
        if (this.uploadingImage != null) {
            this.clearAfterUpdate = true;
        } else {
            this.parentFragment = null;
            this.delegate = null;
        }
    }

    public void openMenu(boolean hasAvatar, final Runnable onDeleteAvatar) {
        CharSequence[] items;
        int[] icons;
        BaseFragment baseFragment = this.parentFragment;
        if (baseFragment != null && baseFragment.getParentActivity() != null) {
            BottomSheet.Builder builder = new BottomSheet.Builder(this.parentFragment.getParentActivity());
            builder.setTitle(LocaleController.getString("ChoosePhoto", R.string.ChoosePhoto));
            if (this.searchAvailable) {
                if (hasAvatar) {
                    items = new CharSequence[]{LocaleController.getString("ChooseTakePhoto", R.string.ChooseTakePhoto), LocaleController.getString("ChooseFromGallery", R.string.ChooseFromGallery), LocaleController.getString("ChooseFromSearch", R.string.ChooseFromSearch), LocaleController.getString("DeletePhoto", R.string.DeletePhoto)};
                    icons = new int[]{R.drawable.menu_camera, R.drawable.profile_photos, R.drawable.menu_search, R.drawable.chats_delete};
                } else {
                    items = new CharSequence[]{LocaleController.getString("ChooseTakePhoto", R.string.ChooseTakePhoto), LocaleController.getString("ChooseFromGallery", R.string.ChooseFromGallery), LocaleController.getString("ChooseFromSearch", R.string.ChooseFromSearch)};
                    icons = new int[]{R.drawable.menu_camera, R.drawable.profile_photos, R.drawable.menu_search};
                }
            } else if (hasAvatar) {
                items = new CharSequence[]{LocaleController.getString("ChooseTakePhoto", R.string.ChooseTakePhoto), LocaleController.getString("ChooseFromGallery", R.string.ChooseFromGallery), LocaleController.getString("DeletePhoto", R.string.DeletePhoto)};
                icons = new int[]{R.drawable.menu_camera, R.drawable.profile_photos, R.drawable.chats_delete};
            } else {
                items = new CharSequence[]{LocaleController.getString("ChooseTakePhoto", R.string.ChooseTakePhoto), LocaleController.getString("ChooseFromGallery", R.string.ChooseFromGallery)};
                icons = new int[]{R.drawable.menu_camera, R.drawable.profile_photos};
            }
            builder.setItems(items, icons, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ImageUpdater$ezaHBy6F5yET4_bsjke7f4eNixo
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$openMenu$0$ImageUpdater(onDeleteAvatar, dialogInterface, i);
                }
            });
            BottomSheet sheet = builder.create();
            this.parentFragment.showDialog(sheet);
            TextView titleView = sheet.getTitleView();
            if (titleView != null) {
                titleView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                titleView.setTextSize(1, 18.0f);
                titleView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            }
            sheet.setItemColor(this.searchAvailable ? 3 : 2, Theme.getColor(Theme.key_dialogTextRed2), Theme.getColor(Theme.key_dialogRedIcon));
        }
    }

    public /* synthetic */ void lambda$openMenu$0$ImageUpdater(Runnable onDeleteAvatar, DialogInterface dialogInterface, int i) {
        if (i == 0) {
            openCamera();
            return;
        }
        if (i == 1) {
            openGallery();
            return;
        }
        if (this.searchAvailable && i == 2) {
            openSearch();
        } else if ((this.searchAvailable && i == 3) || i == 2) {
            onDeleteAvatar.run();
        }
    }

    public void setSearchAvailable(boolean value) {
        this.searchAvailable = value;
    }

    public void setUploadAfterSelect(boolean value) {
        this.uploadAfterSelect = value;
    }

    public void openSearch() {
        if (this.parentFragment == null) {
            return;
        }
        final HashMap<Object, Object> photos = new HashMap<>();
        final ArrayList<Object> order = new ArrayList<>();
        PhotoPickerActivity fragment = new PhotoPickerActivity(0, null, photos, order, new ArrayList(), 1, false, null);
        fragment.setDelegate(new PhotoPickerActivity.PhotoPickerActivityDelegate() { // from class: im.uwrkaxlmjj.ui.components.ImageUpdater.1
            private boolean sendPressed;

            @Override // im.uwrkaxlmjj.ui.PhotoPickerActivity.PhotoPickerActivityDelegate
            public void selectedPhotosChanged() {
            }

            private void sendSelectedPhotos(HashMap<Object, Object> photos2, ArrayList<Object> order2, boolean notify, int scheduleDate) {
            }

            @Override // im.uwrkaxlmjj.ui.PhotoPickerActivity.PhotoPickerActivityDelegate
            public void actionButtonPressed(boolean canceled, boolean notify, int scheduleDate, boolean blnOriginalImg) throws FileNotFoundException {
                if (photos.isEmpty() || ImageUpdater.this.delegate == null || this.sendPressed || canceled) {
                    return;
                }
                this.sendPressed = true;
                ArrayList<SendMessagesHelper.SendingMediaInfo> media = new ArrayList<>();
                for (int a = 0; a < order.size(); a++) {
                    Object object = photos.get(order.get(a));
                    SendMessagesHelper.SendingMediaInfo info = new SendMessagesHelper.SendingMediaInfo();
                    media.add(info);
                    if (object instanceof MediaController.SearchImage) {
                        MediaController.SearchImage searchImage = (MediaController.SearchImage) object;
                        if (searchImage.imagePath != null) {
                            info.path = searchImage.imagePath;
                        } else {
                            info.searchImage = searchImage;
                        }
                        info.caption = searchImage.caption != null ? searchImage.caption.toString() : null;
                        info.entities = searchImage.entities;
                        info.masks = searchImage.stickers.isEmpty() ? null : new ArrayList<>(searchImage.stickers);
                        info.ttl = searchImage.ttl;
                    }
                }
                ImageUpdater.this.didSelectPhotos(media);
            }

            @Override // im.uwrkaxlmjj.ui.PhotoPickerActivity.PhotoPickerActivityDelegate
            public void onCaptionChanged(CharSequence caption) {
            }
        });
        fragment.setInitialSearchString(this.delegate.getInitialSearchString());
        this.parentFragment.presentFragment(fragment);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> photos) throws FileNotFoundException {
        if (!photos.isEmpty()) {
            SendMessagesHelper.SendingMediaInfo info = photos.get(0);
            Bitmap bitmap = null;
            if (info.path != null) {
                bitmap = ImageLoader.loadBitmap(info.path, null, 800.0f, 800.0f, true);
            } else if (info.searchImage != null) {
                if (info.searchImage.photo != null) {
                    TLRPC.PhotoSize photoSize = FileLoader.getClosestPhotoSizeWithSize(info.searchImage.photo.sizes, AndroidUtilities.getPhotoSize());
                    if (photoSize != null) {
                        File path = FileLoader.getPathToAttach(photoSize, true);
                        this.finalPath = path.getAbsolutePath();
                        if (!path.exists()) {
                            path = FileLoader.getPathToAttach(photoSize, false);
                            if (!path.exists()) {
                                path = null;
                            }
                        }
                        if (path == null) {
                            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidLoad);
                            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidFailToLoad);
                            this.uploadingImage = FileLoader.getAttachFileName(photoSize.location);
                            this.imageReceiver.setImage(ImageLocation.getForPhoto(photoSize, info.searchImage.photo), null, null, "jpg", null, 1);
                        } else {
                            bitmap = ImageLoader.loadBitmap(path.getAbsolutePath(), null, 800.0f, 800.0f, true);
                        }
                    }
                } else if (info.searchImage.imageUrl != null) {
                    String md5 = Utilities.MD5(info.searchImage.imageUrl) + "." + ImageLoader.getHttpUrlExtension(info.searchImage.imageUrl, "jpg");
                    File cacheFile = new File(FileLoader.getDirectory(4), md5);
                    this.finalPath = cacheFile.getAbsolutePath();
                    if (!cacheFile.exists() || cacheFile.length() == 0) {
                        this.uploadingImage = info.searchImage.imageUrl;
                        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.httpFileDidLoad);
                        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.httpFileDidFailedLoad);
                        this.imageReceiver.setImage(info.searchImage.imageUrl, null, null, "jpg", 1);
                    } else {
                        bitmap = ImageLoader.loadBitmap(cacheFile.getAbsolutePath(), null, 800.0f, 800.0f, true);
                    }
                } else {
                    bitmap = null;
                }
            }
            processBitmap(bitmap);
        }
    }

    public void openCamera() {
        BaseFragment baseFragment = this.parentFragment;
        if (baseFragment == null || baseFragment.getParentActivity() == null) {
            return;
        }
        try {
            if (Build.VERSION.SDK_INT >= 23 && this.parentFragment.getParentActivity().checkSelfPermission("android.permission.CAMERA") != 0) {
                this.parentFragment.getParentActivity().requestPermissions(new String[]{"android.permission.CAMERA"}, 19);
                return;
            }
            Intent takePictureIntent = new Intent("android.media.action.IMAGE_CAPTURE");
            File image = AndroidUtilities.generatePicturePath();
            if (image != null) {
                if (Build.VERSION.SDK_INT >= 24) {
                    takePictureIntent.putExtra("output", FileProvider.getUriForFile(this.parentFragment.getParentActivity(), "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", image));
                    takePictureIntent.addFlags(2);
                    takePictureIntent.addFlags(1);
                } else {
                    takePictureIntent.putExtra("output", Uri.fromFile(image));
                }
                this.currentPicturePath = image.getAbsolutePath();
            }
            this.parentFragment.startActivityForResult(takePictureIntent, 13);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void openGallery() {
        BaseFragment baseFragment;
        if (this.parentFragment == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 23 && (baseFragment = this.parentFragment) != null && baseFragment.getParentActivity() != null && this.parentFragment.getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0) {
            this.parentFragment.getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 4);
            return;
        }
        PhotoAlbumPickerActivity fragment = new PhotoAlbumPickerActivity(1, false, false, null);
        fragment.setDelegate(new PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate() { // from class: im.uwrkaxlmjj.ui.components.ImageUpdater.2
            @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
            public void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> photos, boolean notify, int scheduleDate, boolean blnOriginalImg) throws FileNotFoundException {
                ImageUpdater.this.didSelectPhotos(photos);
                if (ImageUpdater.this.delegate != null) {
                    ImageUpdater.this.delegate.didSelectPhotos(photos, notify, scheduleDate);
                }
            }

            @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
            public void startPhotoSelectActivity() {
                try {
                    Intent photoPickerIntent = new Intent("android.intent.action.GET_CONTENT");
                    photoPickerIntent.setType("image/*");
                    ImageUpdater.this.parentFragment.startActivityForResult(photoPickerIntent, 14);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
        });
        this.parentFragment.presentFragment(fragment);
    }

    private void startCrop(String path, Uri uri) throws FileNotFoundException {
        try {
            LaunchActivity activity = (LaunchActivity) this.parentFragment.getParentActivity();
            if (activity == null) {
                return;
            }
            Bundle args = new Bundle();
            if (path != null) {
                args.putString("photoPath", path);
            } else if (uri != null) {
                args.putParcelable("photoUri", uri);
            }
            PhotoCropActivity photoCropActivity = new PhotoCropActivity(args);
            photoCropActivity.setDelegate(this);
            activity.lambda$runLinkRequest$26$LaunchActivity(photoCropActivity);
        } catch (Exception e) {
            FileLog.e(e);
            Bitmap bitmap = ImageLoader.loadBitmap(path, uri, 800.0f, 800.0f, true);
            processBitmap(bitmap);
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) throws FileNotFoundException {
        if (resultCode == -1) {
            if (requestCode == 13) {
                PhotoViewer.getInstance().setParentActivity(this.parentFragment.getParentActivity());
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
                PhotoViewer.getInstance().setIsFcCrop(false);
                PhotoViewer.getInstance().openPhotoForSelect(arrayList, 0, 1, new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.components.ImageUpdater.3
                    @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                    public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) throws FileNotFoundException {
                        String path = null;
                        MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) arrayList.get(0);
                        if (photoEntry.imagePath != null) {
                            path = photoEntry.imagePath;
                        } else if (photoEntry.path != null) {
                            path = photoEntry.path;
                        }
                        Bitmap bitmap = ImageLoader.loadBitmap(path, null, 800.0f, 800.0f, true);
                        ImageUpdater.this.processBitmap(bitmap);
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
                return;
            }
            if (requestCode != 14 || data == null || data.getData() == null) {
                return;
            }
            startCrop(null, data.getData());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processBitmap(Bitmap bitmap) {
        if (bitmap == null) {
            return;
        }
        this.bigPhoto = ImageLoader.scaleAndSaveImage(bitmap, 800.0f, 800.0f, 80, false, 320, 320);
        TLRPC.PhotoSize photoSizeScaleAndSaveImage = ImageLoader.scaleAndSaveImage(bitmap, 150.0f, 150.0f, 80, false, 150, 150);
        this.smallPhoto = photoSizeScaleAndSaveImage;
        if (photoSizeScaleAndSaveImage != null) {
            try {
                Bitmap b = BitmapFactory.decodeFile(FileLoader.getPathToAttach(photoSizeScaleAndSaveImage, true).getAbsolutePath());
                String key = this.smallPhoto.location.volume_id + "_" + this.smallPhoto.location.local_id + "@50_50";
                ImageLoader.getInstance().putImageToCache(new BitmapDrawable(b), key);
            } catch (Throwable th) {
            }
        }
        bitmap.recycle();
        if (this.bigPhoto != null) {
            UserConfig.getInstance(this.currentAccount).saveConfig(false);
            this.uploadingImage = FileLoader.getDirectory(4) + "/" + this.bigPhoto.location.volume_id + "_" + this.bigPhoto.location.local_id + ".jpg";
            if (this.uploadAfterSelect) {
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileDidUpload);
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileDidFailUpload);
                FileLoader.getInstance(this.currentAccount).uploadFile(this.uploadingImage, false, true, 16777216);
            }
            ImageUpdaterDelegate imageUpdaterDelegate = this.delegate;
            if (imageUpdaterDelegate != null) {
                imageUpdaterDelegate.didUploadPhoto(null, this.bigPhoto, this.smallPhoto);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.PhotoCropActivity.PhotoEditActivityDelegate
    public void didFinishEdit(Bitmap bitmap) {
        processBitmap(bitmap);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) throws FileNotFoundException {
        if (id == NotificationCenter.FileDidUpload) {
            String location = (String) args[0];
            if (location.equals(this.uploadingImage)) {
                NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileDidUpload);
                NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileDidFailUpload);
                ImageUpdaterDelegate imageUpdaterDelegate = this.delegate;
                if (imageUpdaterDelegate != null) {
                    imageUpdaterDelegate.didUploadPhoto((TLRPC.InputFile) args[1], this.bigPhoto, this.smallPhoto);
                }
                this.uploadingImage = null;
                if (this.clearAfterUpdate) {
                    this.imageReceiver.setImageBitmap((Drawable) null);
                    this.parentFragment = null;
                    this.delegate = null;
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.FileDidFailUpload) {
            String location2 = (String) args[0];
            if (location2.equals(this.uploadingImage)) {
                NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileDidUpload);
                NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileDidFailUpload);
                this.uploadingImage = null;
                if (this.clearAfterUpdate) {
                    this.imageReceiver.setImageBitmap((Drawable) null);
                    this.parentFragment = null;
                    this.delegate = null;
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fileDidLoad || id == NotificationCenter.fileDidFailToLoad || id == NotificationCenter.httpFileDidLoad || id == NotificationCenter.httpFileDidFailedLoad) {
            String path = (String) args[0];
            if (path.equals(this.uploadingImage)) {
                NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidLoad);
                NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidFailToLoad);
                NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.httpFileDidLoad);
                NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.httpFileDidFailedLoad);
                this.uploadingImage = null;
                if (id == NotificationCenter.fileDidLoad || id == NotificationCenter.httpFileDidLoad) {
                    Bitmap bitmap = ImageLoader.loadBitmap(this.finalPath, null, 800.0f, 800.0f, true);
                    processBitmap(bitmap);
                } else {
                    this.imageReceiver.setImageBitmap((Drawable) null);
                }
            }
        }
    }
}
