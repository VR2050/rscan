package kotlin.reflect.jvm.internal.pcollections;

import java.util.Iterator;
import java.util.NoSuchElementException;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class ConsPStack<E> implements Iterable<E> {
    private static final ConsPStack<Object> EMPTY = new ConsPStack<>();
    public final E first;
    public final ConsPStack<E> rest;
    private final int size;

    public static class Itr<E> implements Iterator<E> {
        private ConsPStack<E> next;

        public Itr(ConsPStack<E> consPStack) {
            this.next = consPStack;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return ((ConsPStack) this.next).size > 0;
        }

        @Override // java.util.Iterator
        public E next() {
            ConsPStack<E> consPStack = this.next;
            E e2 = consPStack.first;
            this.next = consPStack.rest;
            return e2;
        }

        @Override // java.util.Iterator
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }

    private ConsPStack() {
        this.size = 0;
        this.first = null;
        this.rest = null;
    }

    public static <E> ConsPStack<E> empty() {
        return (ConsPStack<E>) EMPTY;
    }

    private ConsPStack<E> minus(Object obj) {
        if (this.size == 0) {
            return this;
        }
        if (this.first.equals(obj)) {
            return this.rest;
        }
        ConsPStack<E> minus = this.rest.minus(obj);
        return minus == this.rest ? this : new ConsPStack<>(this.first, minus);
    }

    private ConsPStack<E> subList(int i2) {
        if (i2 < 0 || i2 > this.size) {
            throw new IndexOutOfBoundsException();
        }
        return i2 == 0 ? this : this.rest.subList(i2 - 1);
    }

    public E get(int i2) {
        if (i2 < 0 || i2 > this.size) {
            throw new IndexOutOfBoundsException();
        }
        try {
            return iterator(i2).next();
        } catch (NoSuchElementException unused) {
            throw new IndexOutOfBoundsException(C1499a.m626l("Index: ", i2));
        }
    }

    @Override // java.lang.Iterable
    public Iterator<E> iterator() {
        return iterator(0);
    }

    public ConsPStack<E> plus(E e2) {
        return new ConsPStack<>(e2, this);
    }

    public int size() {
        return this.size;
    }

    private Iterator<E> iterator(int i2) {
        return new Itr(subList(i2));
    }

    private ConsPStack(E e2, ConsPStack<E> consPStack) {
        this.first = e2;
        this.rest = consPStack;
        this.size = consPStack.size + 1;
    }

    public ConsPStack<E> minus(int i2) {
        return minus(get(i2));
    }
}
