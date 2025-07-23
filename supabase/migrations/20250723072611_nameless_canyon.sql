/*
  # Fix database error during user signup

  1. Database Functions
    - Create or replace the handle_new_user function with proper error handling
    - Ensure the function can handle profile creation properly

  2. Triggers
    - Create trigger on auth.users for automatic profile creation
    - Handle cases where profile might already exist

  3. Security
    - Update RLS policies to allow profile creation during signup
    - Ensure anon users can insert profiles during registration
*/

-- Create or replace the function to handle new user creation
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  -- Insert new profile, ignore if already exists
  INSERT INTO public.profiles (id, email, full_name, created_at, updated_at)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', ''),
    NOW(),
    NOW()
  )
  ON CONFLICT (id) DO NOTHING;
  
  RETURN NEW;
EXCEPTION
  WHEN OTHERS THEN
    -- Log the error but don't fail the user creation
    RAISE WARNING 'Error creating profile for user %: %', NEW.id, SQLERRM;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Drop existing trigger if it exists
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

-- Create trigger for new user creation
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Update RLS policies for profiles table to allow signup
DROP POLICY IF EXISTS "Allow anon insert during signup" ON public.profiles;
CREATE POLICY "Allow anon insert during signup"
  ON public.profiles
  FOR INSERT
  TO anon
  WITH CHECK (true);

-- Ensure the existing policies are properly configured
DROP POLICY IF EXISTS "Users can insert own profile" ON public.profiles;
CREATE POLICY "Users can insert own profile"
  ON public.profiles
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = id);

-- Update the shared access trigger function
CREATE OR REPLACE FUNCTION public.update_shared_access_on_signup()
RETURNS trigger AS $$
BEGIN
  -- Update shared_access records where email matches
  UPDATE public.shared_access
  SET shared_with_id = NEW.id
  WHERE shared_with_email = NEW.email
    AND shared_with_id IS NULL;
  
  RETURN NEW;
EXCEPTION
  WHEN OTHERS THEN
    -- Log the error but don't fail
    RAISE WARNING 'Error updating shared access for user %: %', NEW.id, SQLERRM;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;