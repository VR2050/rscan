package im.uwrkaxlmjj.ui.hui.adapter;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.viewpager.widget.PagerAdapter;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class WatchUserPagerAdapter extends PagerAdapter {
    private Context context;
    private List<TLRPC.User> list;

    public WatchUserPagerAdapter(Context context, List<TLRPC.User> list) {
        this.context = context;
        this.list = list;
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public int getCount() {
        return this.list.size();
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public boolean isViewFromObject(View view, Object object) {
        return view == object;
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public Object instantiateItem(ViewGroup viewGroup, int position) {
        BackupImageView iv = new BackupImageView(this.context);
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        TLRPC.User user = this.list.get(position);
        if (user != null) {
            avatarDrawable.setInfo(user);
            iv.setRoundRadius(AndroidUtilities.dp(25.0f));
            iv.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
        }
        viewGroup.addView(iv);
        return iv;
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public float getPageWidth(int position) {
        if (AndroidUtilities.isScreenOriatationPortrait(this.context)) {
            return 0.37f;
        }
        return 0.1f;
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public void destroyItem(ViewGroup container, int position, Object object) {
        container.removeView((View) object);
    }
}
