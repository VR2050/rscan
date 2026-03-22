package p476m.p496b.p500b.p503h;

import android.content.ContentResolver;
import android.database.CharArrayBuffer;
import android.database.ContentObserver;
import android.database.Cursor;
import android.database.CursorWindow;
import android.database.DataSetObserver;
import android.net.Uri;
import android.os.Bundle;

/* renamed from: m.b.b.h.b */
/* loaded from: classes3.dex */
public final class C4943b implements Cursor {

    /* renamed from: c */
    public final CursorWindow f12606c;

    /* renamed from: e */
    public int f12607e;

    /* renamed from: f */
    public final int f12608f;

    public C4943b(CursorWindow cursorWindow) {
        this.f12606c = cursorWindow;
        this.f12608f = cursorWindow.getNumRows();
    }

    @Override // android.database.Cursor, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public void copyStringToBuffer(int i2, CharArrayBuffer charArrayBuffer) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public void deactivate() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public byte[] getBlob(int i2) {
        return this.f12606c.getBlob(this.f12607e, i2);
    }

    @Override // android.database.Cursor
    public int getColumnCount() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public int getColumnIndex(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public int getColumnIndexOrThrow(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public String getColumnName(int i2) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public String[] getColumnNames() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public int getCount() {
        return this.f12606c.getNumRows();
    }

    @Override // android.database.Cursor
    public double getDouble(int i2) {
        return this.f12606c.getDouble(this.f12607e, i2);
    }

    @Override // android.database.Cursor
    public Bundle getExtras() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public float getFloat(int i2) {
        return this.f12606c.getFloat(this.f12607e, i2);
    }

    @Override // android.database.Cursor
    public int getInt(int i2) {
        return this.f12606c.getInt(this.f12607e, i2);
    }

    @Override // android.database.Cursor
    public long getLong(int i2) {
        return this.f12606c.getLong(this.f12607e, i2);
    }

    @Override // android.database.Cursor
    public Uri getNotificationUri() {
        return null;
    }

    @Override // android.database.Cursor
    public int getPosition() {
        return this.f12607e;
    }

    @Override // android.database.Cursor
    public short getShort(int i2) {
        return this.f12606c.getShort(this.f12607e, i2);
    }

    @Override // android.database.Cursor
    public String getString(int i2) {
        return this.f12606c.getString(this.f12607e, i2);
    }

    @Override // android.database.Cursor
    public int getType(int i2) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public boolean getWantsAllOnMoveCalls() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public boolean isAfterLast() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public boolean isBeforeFirst() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public boolean isClosed() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public boolean isFirst() {
        return this.f12607e == 0;
    }

    @Override // android.database.Cursor
    public boolean isLast() {
        return this.f12607e == this.f12608f - 1;
    }

    @Override // android.database.Cursor
    public boolean isNull(int i2) {
        return this.f12606c.isNull(this.f12607e, i2);
    }

    @Override // android.database.Cursor
    public boolean move(int i2) {
        return moveToPosition(this.f12607e + i2);
    }

    @Override // android.database.Cursor
    public boolean moveToFirst() {
        this.f12607e = 0;
        return this.f12608f > 0;
    }

    @Override // android.database.Cursor
    public boolean moveToLast() {
        int i2 = this.f12608f;
        if (i2 <= 0) {
            return false;
        }
        this.f12607e = i2 - 1;
        return true;
    }

    @Override // android.database.Cursor
    public boolean moveToNext() {
        int i2 = this.f12607e;
        if (i2 >= this.f12608f - 1) {
            return false;
        }
        this.f12607e = i2 + 1;
        return true;
    }

    @Override // android.database.Cursor
    public boolean moveToPosition(int i2) {
        if (i2 < 0 || i2 >= this.f12608f) {
            return false;
        }
        this.f12607e = i2;
        return true;
    }

    @Override // android.database.Cursor
    public boolean moveToPrevious() {
        int i2 = this.f12607e;
        if (i2 <= 0) {
            return false;
        }
        this.f12607e = i2 - 1;
        return true;
    }

    @Override // android.database.Cursor
    public void registerContentObserver(ContentObserver contentObserver) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public void registerDataSetObserver(DataSetObserver dataSetObserver) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public boolean requery() {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public Bundle respond(Bundle bundle) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public void setNotificationUri(ContentResolver contentResolver, Uri uri) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public void unregisterContentObserver(ContentObserver contentObserver) {
        throw new UnsupportedOperationException();
    }

    @Override // android.database.Cursor
    public void unregisterDataSetObserver(DataSetObserver dataSetObserver) {
        throw new UnsupportedOperationException();
    }
}
