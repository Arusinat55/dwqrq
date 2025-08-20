import { cn } from '@/lib/utils';
import { ButtonHTMLAttributes, forwardRef } from 'react';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, children, disabled, ...props }, ref) => {
    const getVariantClass = () => {
      switch (variant) {
        case 'primary': return 'btn btn-primary';
        case 'secondary': return 'btn bg-gray-600 text-white hover:bg-gray-700';
        case 'outline': return 'btn btn-outline';
        case 'ghost': return 'btn btn-ghost';
        case 'danger': return 'btn bg-red-600 text-white hover:bg-red-700';
        default: return 'btn btn-primary';
      }
    };

    const getSizeClass = () => {
      switch (size) {
        case 'sm': return 'btn-sm';
        case 'lg': return 'btn-lg';
        default: return '';
      }
    };

    return (
      <button
        ref={ref}
        className={cn(getVariantClass(), getSizeClass(), 'w-full', className)}
        disabled={disabled || loading}
        {...props}
      >
        {loading && (
          <div className="spinner w-4 h-4 mr-2"></div>
        )}
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';

export default Button;