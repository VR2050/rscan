package im.uwrkaxlmjj.ui.components;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import androidx.core.content.FileProvider;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WallpaperUpdater {
    private String currentPicturePath;
    private File currentWallpaperPath;
    private WallpaperUpdaterDelegate delegate;
    private Activity parentActivity;
    private BaseFragment parentFragment;
    private File picturePath = null;

    public interface WallpaperUpdaterDelegate {
        void didSelectWallpaper(File file, Bitmap bitmap, boolean z);

        void needOpenColorPicker();
    }

    public WallpaperUpdater(Activity activity, BaseFragment fragment, WallpaperUpdaterDelegate wallpaperUpdaterDelegate) {
        this.parentActivity = activity;
        this.parentFragment = fragment;
        this.delegate = wallpaperUpdaterDelegate;
    }

    public void showAlert(final boolean fromTheme) {
        CharSequence[] items;
        int[] icons;
        BottomSheet.Builder builder = new BottomSheet.Builder(this.parentActivity);
        builder.setTitle(LocaleController.getString("ChoosePhoto", R.string.ChoosePhoto));
        if (fromTheme) {
            items = new CharSequence[]{LocaleController.getString("ChooseTakePhoto", R.string.ChooseTakePhoto), LocaleController.getString("SelectFromGallery", R.string.SelectFromGallery), LocaleController.getString("SelectColor", R.string.SelectColor), LocaleController.getString("Default", R.string.Default)};
            icons = null;
        } else {
            items = new CharSequence[]{LocaleController.getString("ChooseTakePhoto", R.string.ChooseTakePhoto), LocaleController.getString("SelectFromGallery", R.string.SelectFromGallery)};
            icons = new int[]{R.drawable.menu_camera, R.drawable.profile_photos};
        }
        builder.setItems(items, icons, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$WallpaperUpdater$Sy06SVn4SqIj-LVm1FhA1I9ha2U
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showAlert$0$WallpaperUpdater(fromTheme, dialogInterface, i);
            }
        });
        builder.show();
    }

    public /* synthetic */ void lambda$showAlert$0$WallpaperUpdater(boolean fromTheme, DialogInterface dialogInterface, int i) {
        try {
            if (i == 0) {
                try {
                    Intent takePictureIntent = new Intent("android.media.action.IMAGE_CAPTURE");
                    File image = AndroidUtilities.generatePicturePath();
                    if (image != null) {
                        if (Build.VERSION.SDK_INT >= 24) {
                            takePictureIntent.putExtra("output", FileProvider.getUriForFile(this.parentActivity, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", image));
                            takePictureIntent.addFlags(2);
                            takePictureIntent.addFlags(1);
                        } else {
                            takePictureIntent.putExtra("output", Uri.fromFile(image));
                        }
                        this.currentPicturePath = image.getAbsolutePath();
                    }
                    this.parentActivity.startActivityForResult(takePictureIntent, 10);
                } catch (Exception e) {
                    FileLog.e(e);
                }
                return;
            }
            if (i == 1) {
                openGallery();
                return;
            }
            if (fromTheme) {
                if (i == 2) {
                    this.delegate.needOpenColorPicker();
                } else if (i == 3) {
                    this.delegate.didSelectWallpaper(null, null, false);
                }
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    public void openGallery() {
        if (this.parentFragment != null) {
            if (Build.VERSION.SDK_INT >= 23 && this.parentFragment.getParentActivity() != null && this.parentFragment.getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0) {
                this.parentFragment.getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 4);
                return;
            }
            PhotoAlbumPickerActivity fragment = new PhotoAlbumPickerActivity(2, false, false, null);
            fragment.setAllowSearchImages(false);
            fragment.setDelegate(new PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate() { // from class: im.uwrkaxlmjj.ui.components.WallpaperUpdater.1
                @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
                public void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> photos, boolean notify, int scheduleDate, boolean blnOriginalImg) {
                    WallpaperUpdater.this.didSelectPhotos(photos);
                }

                @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
                public void startPhotoSelectActivity() {
                    try {
                        Intent photoPickerIntent = new Intent("android.intent.action.PICK");
                        photoPickerIntent.setType("image/*");
                        WallpaperUpdater.this.parentActivity.startActivityForResult(photoPickerIntent, 11);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                }
            });
            this.parentFragment.presentFragment(fragment);
            return;
        }
        Intent photoPickerIntent = new Intent("android.intent.action.PICK");
        photoPickerIntent.setType("image/*");
        this.parentActivity.startActivityForResult(photoPickerIntent, 11);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> photos) {
        try {
            if (!photos.isEmpty()) {
                SendMessagesHelper.SendingMediaInfo info = photos.get(0);
                if (info.path != null) {
                    this.currentWallpaperPath = new File(FileLoader.getDirectory(4), Utilities.random.nextInt() + ".jpg");
                    android.graphics.Point screenSize = AndroidUtilities.getRealScreenSize();
                    Bitmap bitmap = ImageLoader.loadBitmap(info.path, null, (float) screenSize.x, (float) screenSize.y, true);
                    FileOutputStream stream = new FileOutputStream(this.currentWallpaperPath);
                    bitmap.compress(Bitmap.CompressFormat.JPEG, 87, stream);
                    this.delegate.didSelectWallpaper(this.currentWallpaperPath, bitmap, true);
                }
            }
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    public void cleanup() {
    }

    public String getCurrentPicturePath() {
        return this.currentPicturePath;
    }

    public void setCurrentPicturePath(String value) {
        this.currentPicturePath = value;
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:11:0x005f -> B:39:0x006f). Please report as a decompilation issue!!! */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == -1) {
            if (requestCode == 10) {
                AndroidUtilities.addMediaToGallery(this.currentPicturePath);
                FileOutputStream stream = null;
                try {
                    try {
                        try {
                            this.currentWallpaperPath = new File(FileLoader.getDirectory(4), Utilities.random.nextInt() + ".jpg");
                            android.graphics.Point screenSize = AndroidUtilities.getRealScreenSize();
                            Bitmap bitmap = ImageLoader.loadBitmap(this.currentPicturePath, null, (float) screenSize.x, (float) screenSize.y, true);
                            stream = new FileOutputStream(this.currentWallpaperPath);
                            bitmap.compress(Bitmap.CompressFormat.JPEG, 87, stream);
                            this.delegate.didSelectWallpaper(this.currentWallpaperPath, bitmap, false);
                            stream.close();
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    } catch (Exception e2) {
                        FileLog.e(e2);
                        if (stream != null) {
                            stream.close();
                        }
                        this.currentPicturePath = null;
                        return;
                    }
                    this.currentPicturePath = null;
                    return;
                } catch (Throwable th) {
                    if (stream != null) {
                        try {
                            stream.close();
                        } catch (Exception e3) {
                            FileLog.e(e3);
                        }
                    }
                    throw th;
                }
            }
            if (requestCode != 11 || data == null || data.getData() == null) {
                return;
            }
            try {
                this.currentWallpaperPath = new File(FileLoader.getDirectory(4), Utilities.random.nextInt() + ".jpg");
                android.graphics.Point screenSize2 = AndroidUtilities.getRealScreenSize();
                Bitmap bitmap2 = ImageLoader.loadBitmap(null, data.getData(), (float) screenSize2.x, (float) screenSize2.y, true);
                bitmap2.compress(Bitmap.CompressFormat.JPEG, 87, new FileOutputStream(this.currentWallpaperPath));
                this.delegate.didSelectWallpaper(this.currentWallpaperPath, bitmap2, false);
            } catch (Exception e4) {
                FileLog.e(e4);
            }
        }
    }
}
