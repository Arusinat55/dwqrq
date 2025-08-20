import { ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, children, disabled, ...props }, ref) => {
    const variants = {
      primary: 'btn-primary',
      secondary: 'bg-gray-600 text-white shadow hover:bg-gray-700',
      outline: 'btn-outline',
      ghost: 'btn-ghost',
      danger: 'bg-red-600 text-white shadow hover:bg-red-700',
    };

    const sizes = {
      sm: 'btn-sm',
      md: 'h-9 px-4 py-2',
      lg: 'btn-lg',
    };

    return (
      <button
        ref={ref}
        className={cn(
          'btn',
          variants[variant],
          sizes[size],
          className
        )}
        disabled={disabled || loading}
        {...props}
      >
        {loading && (
          <div className="spinner w-4 h-4 mr-2" />
        )}
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';

export default Button;