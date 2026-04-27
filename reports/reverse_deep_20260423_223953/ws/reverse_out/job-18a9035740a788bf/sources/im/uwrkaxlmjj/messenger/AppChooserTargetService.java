package im.uwrkaxlmjj.messenger;

import android.content.ComponentName;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Icon;
import android.os.Bundle;
import android.service.chooser.ChooserTarget;
import android.service.chooser.ChooserTargetService;
import android.text.TextUtils;
import im.uwrkaxlmjj.sqlite.SQLiteCursor;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.LaunchActivity;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;

/* JADX INFO: loaded from: classes2.dex */
public class AppChooserTargetService extends ChooserTargetService {
    private RectF bitmapRect;
    private Paint roundPaint;

    @Override // android.service.chooser.ChooserTargetService
    public List<ChooserTarget> onGetChooserTargets(ComponentName targetActivityName, IntentFilter matchedFilter) {
        final int currentAccount = UserConfig.selectedAccount;
        final List<ChooserTarget> targets = new ArrayList<>();
        if (!UserConfig.getInstance(currentAccount).isClientActivated()) {
            return targets;
        }
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        if (!preferences.getBoolean("direct_share", true)) {
            return targets;
        }
        ImageLoader.getInstance();
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final ComponentName componentName = new ComponentName(getPackageName(), LaunchActivity.class.getCanonicalName());
        MessagesStorage.getInstance(currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AppChooserTargetService$jh03UEaInSBtCCZTXwymmR3Mv3E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onGetChooserTargets$0$AppChooserTargetService(currentAccount, targets, componentName, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e(e);
        }
        return targets;
    }

    public /* synthetic */ void lambda$onGetChooserTargets$0$AppChooserTargetService(int currentAccount, List targets, ComponentName componentName, CountDownLatch countDownLatch) {
        String name;
        Icon icon;
        ArrayList<Integer> dialogs = new ArrayList<>();
        ArrayList<TLRPC.Chat> chats = new ArrayList<>();
        ArrayList<TLRPC.User> users = new ArrayList<>();
        boolean z = true;
        try {
            ArrayList<Integer> usersToLoad = new ArrayList<>();
            usersToLoad.add(Integer.valueOf(UserConfig.getInstance(currentAccount).getClientUserId()));
            ArrayList<Integer> chatsToLoad = new ArrayList<>();
            SQLiteCursor cursor = MessagesStorage.getInstance(currentAccount).getDatabase().queryFinalized(String.format(Locale.US, "SELECT did FROM dialogs ORDER BY date DESC LIMIT %d,%d", 0, 30), new Object[0]);
            while (cursor.next()) {
                long id = cursor.longValue(0);
                int lower_id = (int) id;
                if (lower_id != 0) {
                    if (lower_id > 0) {
                        if (!usersToLoad.contains(Integer.valueOf(lower_id))) {
                            usersToLoad.add(Integer.valueOf(lower_id));
                        }
                    } else if (!chatsToLoad.contains(Integer.valueOf(-lower_id))) {
                        chatsToLoad.add(Integer.valueOf(-lower_id));
                    }
                    dialogs.add(Integer.valueOf(lower_id));
                    if (dialogs.size() == 8) {
                        break;
                    }
                }
            }
            cursor.dispose();
            if (!chatsToLoad.isEmpty()) {
                MessagesStorage.getInstance(currentAccount).getChatsInternal(TextUtils.join(",", chatsToLoad), chats);
            }
            if (!usersToLoad.isEmpty()) {
                MessagesStorage.getInstance(currentAccount).getUsersInternal(TextUtils.join(",", usersToLoad), users);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        SharedConfig.directShareHash = Utilities.random.nextLong();
        ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", 0).edit().putLong("directShareHash", SharedConfig.directShareHash).commit();
        int a = 0;
        while (a < dialogs.size()) {
            Bundle extras = new Bundle();
            Icon icon2 = null;
            String name2 = null;
            int id2 = dialogs.get(a).intValue();
            if (id2 > 0) {
                int b = 0;
                while (true) {
                    if (b >= users.size()) {
                        break;
                    }
                    TLRPC.User user = users.get(b);
                    if (user.id != id2) {
                        b++;
                    } else if (!user.bot) {
                        extras.putLong("dialogId", id2);
                        extras.putLong("hash", SharedConfig.directShareHash);
                        if (user.photo != null && user.photo.photo_small != null) {
                            icon2 = createRoundBitmap(FileLoader.getPathToAttach(user.photo.photo_small, z));
                        }
                        name2 = ContactsController.formatName(user.first_name, user.last_name);
                    }
                }
                name = name2;
            } else {
                int b2 = 0;
                while (true) {
                    if (b2 >= chats.size()) {
                        break;
                    }
                    TLRPC.Chat chat = chats.get(b2);
                    if (chat.id != (-id2)) {
                        b2++;
                    } else {
                        if (ChatObject.isNotInChat(chat) || (ChatObject.isChannel(chat) && !chat.megagroup)) {
                            break;
                        }
                        extras.putLong("dialogId", id2);
                        extras.putLong("hash", SharedConfig.directShareHash);
                        if (chat.photo != null && chat.photo.photo_small != null) {
                            icon2 = createRoundBitmap(FileLoader.getPathToAttach(chat.photo.photo_small, z));
                        }
                        name = chat.title;
                    }
                }
                name = null;
            }
            if (name != null) {
                if (icon2 != null) {
                    icon = icon2;
                } else {
                    icon = Icon.createWithResource(ApplicationLoader.applicationContext, mpEIGo.juqQQs.esbSDO.R.drawable.logo_avatar);
                }
                targets.add(new ChooserTarget(name, icon, 1.0f, componentName, extras));
            }
            a++;
            z = true;
        }
        countDownLatch.countDown();
    }

    private Icon createRoundBitmap(File path) {
        try {
            Bitmap bitmap = BitmapFactory.decodeFile(path.toString());
            if (bitmap != null) {
                Bitmap result = Bitmap.createBitmap(bitmap.getWidth(), bitmap.getHeight(), Bitmap.Config.ARGB_8888);
                result.eraseColor(0);
                Canvas canvas = new Canvas(result);
                BitmapShader shader = new BitmapShader(bitmap, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
                if (this.roundPaint == null) {
                    this.roundPaint = new Paint(1);
                    this.bitmapRect = new RectF();
                }
                this.roundPaint.setShader(shader);
                this.bitmapRect.set(0.0f, 0.0f, bitmap.getWidth(), bitmap.getHeight());
                canvas.drawRoundRect(this.bitmapRect, bitmap.getWidth(), bitmap.getHeight(), this.roundPaint);
                return Icon.createWithBitmap(result);
            }
            return null;
        } catch (Throwable e) {
            FileLog.e(e);
            return null;
        }
    }
}
