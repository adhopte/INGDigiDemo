export interface Product { id: string; price: number; icon: string }
export const PRODUCTS: Product[] = [
  { id: 'p1', price: 59.9, icon: '' },
  { id: 'p2', price: 24.5, icon: '' },
  { id: 'p3', price: 129, icon: '' },
  { id: 'p4', price: 39.99, icon: '' },
  { id: 'p5', price: 15.2, icon: '' },
  { id: 'p6', price: 89, icon: '' },
];
export const productById = (id: string) => PRODUCTS.find((p) => p.id === id);
export const SHIPPING = 4.9;
